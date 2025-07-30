import os
import boto3

def send_file_transfer_sns_alert(
    trace_id, s3_files, box_files, ftp_files, checksum_results, errors=None, warnings=None, function_name="N/A"
):
    """
    Compose and send an SNS alert about the transfer outcome.
    """
    sns_client = boto3.client("sns")
    sns_topic_arn = os.getenv("SNS_TOPIC_ARN")

    body = f"""[ALERT] File Transfer Summary
Function: {function_name}
Trace ID: {trace_id}

Transferred to S3: {', '.join(s3_files) if s3_files else 'None'}
Transferred to Box: {', '.join(box_files) if box_files else 'None'}
Transferred to FTP: {', '.join(ftp_files) if ftp_files else 'None'}

Checksums:
""" + "\n".join([f"  {f['file']}: {f['status']}" for f in checksum_results])

    if warnings:
        body += "\nWarnings:\n" + "\n".join([str(w) for w in warnings])
    if errors:
        body += "\nErrors:\n" + "\n".join([str(e) for e in errors])

    if sns_topic_arn:
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Subject=f"File Transfer Alert (Trace ID: {trace_id})",
            Message=body
        )
    else:
        print("[WARNING] SNS_TOPIC_ARN is not set. No alert sent.")
