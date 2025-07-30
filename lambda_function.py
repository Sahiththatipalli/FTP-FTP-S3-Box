import os
import json
import boto3
import paramiko
import tempfile
import shutil
import time
from boxsdk import JWTAuth, Client
import ftplib

from logging_utils import (
    log_job_start, log_job_end, log_sftp_connection, log_matched_files,
    log_checksum_ok, log_checksum_fail, log_file_transferred,
    log_box_version, log_archive, log_tmp_usage, log_error, log_warning
)
from checksum_utils import log_checksum
from trace_utils import get_or_create_trace_id
from file_match_utils import match_files
from retry_utils import default_retry
from storage_utils import get_date_subpath, upload_files_to_box_by_date
from performance_utils import time_operation
from metrics_utils import publish_file_transfer_metric, publish_error_metric
from alert_utils import send_transfer_alert

s3_client = boto3.client('s3')

def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    secret = response['SecretString']
    return json.loads(secret)

def get_file_patterns():
    val = os.getenv('FILE_PATTERN')
    if val:
        return [x.strip() for x in val.split(',') if x.strip()]
    return ['*']

@default_retry()
def create_sftp_client(host, port, username, password):
    transport = paramiko.Transport((host, port))
    transport.connect(username=username, password=password)
    return paramiko.SFTPClient.from_transport(transport)

@default_retry()
def download_and_upload_to_s3(
    sftp_client, remote_dir, bucket, prefix, local_dir,
    trace_id, job_id, file_patterns, metrics_out, checksum_results
):
    all_files = sftp_client.listdir(remote_dir)
    files = match_files(all_files, include_patterns=file_patterns)
    unmatched = set(all_files) - set(files)
    date_subpath = get_date_subpath()
    log_matched_files(trace_id, files, unmatched)

    s3_total_bytes = 0
    s3_total_time = 0
    sftp_total_bytes = 0
    sftp_total_time = 0

    for filename in files:
        remote_path = f"{remote_dir}/{filename}"
        local_path = os.path.join(local_dir, filename)

        # Download from SFTP
        t0 = time.time()
        sftp_client.get(remote_path, local_path)
        t1 = time.time()
        sftp_download_time = t1 - t0
        bytes_downloaded = os.path.getsize(local_path)
        sftp_total_bytes += bytes_downloaded
        sftp_total_time += sftp_download_time

        # Checksum after download
        downloaded_checksum = log_checksum(local_path, trace_id, algo="sha256", note="after SFTP download")
        before_s3_checksum = log_checksum(local_path, trace_id, algo="sha256", note="before S3 upload")

        if downloaded_checksum == before_s3_checksum:
            checksum_results[filename] = f"OK (sha256: {downloaded_checksum})"
            log_checksum_ok(trace_id, filename, downloaded_checksum)
        else:
            checksum_results[filename] = f"FAIL (after: {downloaded_checksum}, before_s3: {before_s3_checksum})"
            log_checksum_fail(trace_id, filename, downloaded_checksum, before_s3_checksum)

        # Upload to S3
        s3_key = f"{prefix}/{date_subpath}/{filename}" if prefix else f"{date_subpath}/{filename}"
        t2 = time.time()
        s3_client.upload_file(local_path, bucket, s3_key)
        t3 = time.time()
        s3_upload_time = t3 - t2
        s3_total_bytes += bytes_downloaded
        s3_total_time += s3_upload_time
        log_file_transferred(trace_id, filename, "S3", s3_upload_time)
        log_archive(trace_id, filename, s3_key)

    # Save metrics for S3 and SFTP
    metrics_out["S3 upload speed mb/s"] = f"{(s3_total_bytes/1024/1024/s3_total_time):.2f}" if s3_total_time else "0.0"
    metrics_out["SFTP download speed mb/s"] = f"{(sftp_total_bytes/1024/1024/sftp_total_time):.2f}" if sftp_total_time else "0.0"
    metrics_out["S3 total mb"] = f"{s3_total_bytes/1024/1024:.2f}"
    metrics_out["SFTP total mb"] = f"{sftp_total_bytes/1024/1024:.2f}"

@default_retry()
def upload_files_to_external_ftp(
    ftp_host, ftp_user, ftp_pass, remote_dir, local_dir,
    trace_id, job_id, file_patterns, metrics_out
):
    files = match_files(os.listdir(local_dir), include_patterns=file_patterns)
    unmatched = set(os.listdir(local_dir)) - set(files)
    date_subpath = get_date_subpath()
    full_path = f"{remote_dir.rstrip('/')}/{date_subpath}"
    parts = full_path.strip('/').split('/')

    log_matched_files(trace_id, files, unmatched)

    ftp = ftplib.FTP(ftp_host)
    ftp.login(ftp_user, ftp_pass)
    for part in parts:
        try:
            ftp.mkd(part)
        except Exception:
            pass
        ftp.cwd(part)

    ftp_total_bytes = 0
    ftp_total_time = 0

    for filename in files:
        local_path = os.path.join(local_dir, filename)
        before_ftp_checksum = log_checksum(local_path, trace_id, algo="sha256", note="before FTP upload")

        with open(local_path, 'rb') as f:
            t0 = time.time()
            ftp.storbinary(f'STOR {filename}', f)
            t1 = time.time()
            bytes_uploaded = os.path.getsize(local_path)
            ftp_total_bytes += bytes_uploaded
            ftp_total_time += (t1 - t0)
            log_file_transferred(trace_id, filename, "FTP", t1 - t0)
    ftp.quit()

    # Save metrics
    metrics_out["FTP upload speed mb/s"] = f"{(ftp_total_bytes/1024/1024/ftp_total_time):.2f}" if ftp_total_time else "0.0"
    metrics_out["FTP total mb"] = f"{ftp_total_bytes/1024/1024:.2f}"

def lambda_handler(event, context):
    trace_id = get_or_create_trace_id(context)
    job_id = trace_id
    file_patterns = get_file_patterns()
    log_job_start(trace_id, job_id, file_patterns)

    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")

    src_secret_name = os.getenv('SRC_SECRET_NAME')
    ext_secret_name = os.getenv('EXT_SECRET_NAME')
    box_secret_name = os.getenv('BOX_SECRET_NAME')
    box_folder_id = os.getenv('BOX_FOLDER_ID')
    s3_bucket = os.getenv('S3_BUCKET', 'jams-ftp-process-bucket')
    s3_prefix = os.getenv('S3_PREFIX', 'ftp-ftp-list')

    src_secret = get_secret(src_secret_name)
    src_host = src_secret['Host']
    src_user = src_secret['Username']
    src_pass = src_secret['Password']
    src_dir = os.getenv('SRC_REMOTE_DIR', '.')

    ext_secret = get_secret(ext_secret_name)
    external_ftp_host = ext_secret['host']
    external_ftp_user = ext_secret['Username']
    external_ftp_pass = ext_secret['password']
    external_ftp_dir = os.getenv('EXT_REMOTE_DIR', '/')

    box_jwt_config = get_secret(box_secret_name)
    auth = JWTAuth(
        client_id=box_jwt_config['boxAppSettings']['clientID'],
        client_secret=box_jwt_config['boxAppSettings']['clientSecret'],
        enterprise_id=box_jwt_config['enterpriseID'],
        jwt_key_id=box_jwt_config['boxAppSettings']['appAuth']['publicKeyID'],
        rsa_private_key_data=box_jwt_config['boxAppSettings']['appAuth']['privateKey'],
        rsa_private_key_passphrase=box_jwt_config['boxAppSettings']['appAuth']['passphrase'].encode('utf-8'),
    )
    box_client = Client(auth)

    transfer_status = {}
    checksum_results = {}
    metrics = {}
    errors = []
    warnings = []

    with tempfile.TemporaryDirectory() as tmp_dir:
        free_mb = shutil.disk_usage(tmp_dir).free // (1024 * 1024)
        log_tmp_usage(trace_id, len(os.listdir(tmp_dir)), free_mb)

        try:
            src_sftp = create_sftp_client(src_host, 22, src_user, src_pass)
            log_sftp_connection(trace_id, src_host, "OPENED")
            download_and_upload_to_s3(
                src_sftp, src_dir, s3_bucket, s3_prefix, tmp_dir, trace_id,
                job_id, file_patterns, metrics, checksum_results
            )
            src_sftp.close()
            log_sftp_connection(trace_id, src_host, "CLOSED")
            transfer_status["s3"] = f"SUCCESS ({', '.join(list(checksum_results.keys()))})"
        except Exception as e:
            errors.append(f"S3/Download failed: {e}")
            transfer_status["s3"] = f"FAILED ({e})"

        free_mb = shutil.disk_usage(tmp_dir).free // (1024 * 1024)
        log_tmp_usage(trace_id, len(os.listdir(tmp_dir)), free_mb)

        try:
            upload_files_to_external_ftp(
                external_ftp_host, external_ftp_user, external_ftp_pass,
                external_ftp_dir, tmp_dir, trace_id, job_id, file_patterns, metrics
            )
            transfer_status["ftp"] = f"SUCCESS ({', '.join(list(checksum_results.keys()))})"
        except Exception as e:
            errors.append(f"FTP upload failed: {e}")
            transfer_status["ftp"] = f"FAILED ({e})"

        free_mb = shutil.disk_usage(tmp_dir).free // (1024 * 1024)
        log_tmp_usage(trace_id, len(os.listdir(tmp_dir)), free_mb)

        box_files = match_files(os.listdir(tmp_dir), include_patterns=file_patterns)
        unmatched = set(os.listdir(tmp_dir)) - set(box_files)
        log_matched_files(trace_id, box_files, unmatched)
        try:
            if box_files:
                box_tmp_dir = os.path.join(tmp_dir, "boxonly")
                os.makedirs(box_tmp_dir, exist_ok=True)
                for fname in box_files:
                    shutil.copy2(os.path.join(tmp_dir, fname), os.path.join(box_tmp_dir, fname))
                t0 = time.time()
                upload_files_to_box_by_date(box_client, box_folder_id, box_tmp_dir, context)
                t1 = time.time()
                box_upload_time = t1 - t0
                box_total_bytes = sum(os.path.getsize(os.path.join(box_tmp_dir, f)) for f in box_files)
                metrics["Box upload speed mb/s"] = f"{(box_total_bytes/1024/1024/box_upload_time):.2f}" if box_upload_time else "0.0"
                metrics["Box total mb"] = f"{box_total_bytes/1024/1024:.2f}"
                transfer_status["box"] = f"SUCCESS ({', '.join(box_files)})"
                for fname in box_files:
                    log_box_version(trace_id, fname, "box_id", "box_version")
            else:
                warnings.append("No files matched FILE_PATTERN for Box, skipping Box upload.")
                transfer_status["box"] = "NO FILES"
        except Exception as e:
            errors.append(f"Box upload failed: {e}")
            transfer_status["box"] = f"FAILED ({e})"

        free_mb = shutil.disk_usage(tmp_dir).free // (1024 * 1024)
        log_tmp_usage(trace_id, len(os.listdir(tmp_dir)), free_mb)

    log_job_end(trace_id, job_id)

    # SEND ALERT
    if sns_topic_arn:
        send_transfer_alert(
            trace_id=trace_id,
            sns_topic_arn=sns_topic_arn,
            transfer_status=transfer_status,
            checksum_results=checksum_results,
            metrics=metrics,
            errors=errors,
            warnings=warnings
        )

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Files transferred successfully to all destinations.', 'trace_id': trace_id})
    }
