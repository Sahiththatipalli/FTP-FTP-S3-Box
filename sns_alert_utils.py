import boto3
import os

def send_file_transfer_sns_alert(
    sns_topic_arn,
    trace_id,
    transfer_status,
    checksum_status,
    metrics,
    errors,
    warnings
):
    sns = boto3.client("sns")
    msg_lines = []

    msg_lines.append("AWS Lambda File Transfer Alert")
    msg_lines.append(f"Trace ID: {trace_id}\n")

    msg_lines.append("==== Transfer Status ====")
    for dest in ("s3", "ftp", "box"):
        label = dest.upper()
        stat = transfer_status.get(dest, "N/A")
        msg_lines.append(f"- {label}: {stat}")
    msg_lines.append("")

    msg_lines.append("==== Checksum Results ====")
    for filename, status in checksum_status.items():
        msg_lines.append(f"- {filename}: {status}")
    if not checksum_status:
        msg_lines.append("No checksum data available.")
    msg_lines.append("")

    msg_lines.append("==== Metrics ====")
    for key, val in metrics.items():
        msg_lines.append(f"- {key}: {val}")
    if not metrics:
        msg_lines.append("No metric data.")
    msg_lines.append("")

    if errors:
        msg_lines.append("==== ERRORS ====")
        for err in errors:
            msg_lines.append(f"- {err}")
        msg_lines.append("")
    if warnings:
        msg_lines.append("==== WARNINGS ====")
        for w in warnings:
            msg_lines.append(f"- {w}")
        msg_lines.append("")

    msg_lines.append("Automated Lambda SNS Alert. See CloudWatch for full logs.\n")

    message = "\n".join(msg_lines)
    subject = f"Lambda File Transfer: Trace {trace_id} - "
    if errors:
        subject += "ERROR"
    else:
        subject += "SUCCESS"

    # Send SNS
    if sns_topic_arn:
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=subject,
            Message=message
        )

