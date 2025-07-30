import logging
import re

# --- Sanitizer function (yours, with slight expansion) ---
def sanitize_logs(text: str) -> str:
    if not text:
        return ""
    # Remove ANSI color codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    text = ansi_escape.sub('', text)

    # Mask common secret patterns
    group_patterns = [
        (re.compile(r'(\"?(Authorization|authorization)\"?\s*:\s*\")[^\"]+(\")'), r'\1***REDACTED***\3'),
        (re.compile(r'(\"?(access_token|refresh_token|api_key|client_secret)\"?\s*:\s*\")[^\"]+(\")'), r'\1***REDACTED***\3'),
    ]
    simple_patterns = [
        re.compile(r'(Authorization|authorization):\s*[\w\-\.]+'),
        re.compile(r'(access_token|refresh_token|api_key|client_secret)\s*=\s*\S+'),
        re.compile(r'(password|Password|pwd)\s*=\s*[^&\s]+'),
    ]
    for pattern, repl in group_patterns:
        text = pattern.sub(repl, text)
    for pattern in simple_patterns:
        text = pattern.sub(r'\1: ***REDACTED***', text)
    # Remove whole lines with server: nginx, headers, cookies if you want
    noisy_lines = [
        r'.*server.*nginx.*',
        r'.*Set-Cookie.*',
        r'.*content-type.*',
        r'.*x-envoy-upstream-service-time.*',
    ]
    for pattern in noisy_lines:
        text = "\n".join([l for l in text.splitlines() if not re.search(pattern, l, re.IGNORECASE)])
    return text

# --- Custom Formatter that sanitizes each message ---
class SanitizingFormatter(logging.Formatter):
    def format(self, record):
        record.msg = sanitize_logs(str(record.getMessage()))
        record.args = None  # <- This line is the key!
        return super().format(record)


# Attach formatter to root logger
def setup_sanitizing_logger():
    logger = logging.getLogger()
    for handler in logger.handlers:
        handler.setFormatter(SanitizingFormatter("%(levelname)s %(asctime)s %(message)s"))
    # If there are no handlers, add a default one
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(SanitizingFormatter("%(levelname)s %(asctime)s %(message)s"))
        logger.addHandler(handler)

# --- Use everywhere in your code after logger setup ---
setup_sanitizing_logger()
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.getLogger("boxsdk").setLevel(logging.WARNING)

# --- Example log helpers (customize as needed) ---
def log_with_id(logger, transfer_id, level, message):
    prefix = f"[TRANSFER:{transfer_id}]"
    sanitized = sanitize_logs(message)
    full_message = f"{prefix} {sanitized}"
    getattr(logger, level)(full_message)

def log_job_start(trace_id, job_id, patterns):
    logger.info(f"[{trace_id}] [JOB {job_id}] Starting transfer: patterns {patterns}")

def log_job_end(trace_id, job_id):
    logger.info(f"[{trace_id}] [JOB {job_id}] Transfer completed.")

def log_sftp_connection(trace_id, host, action):
    logger.info(f"[{trace_id}] SFTP session {action} to {host}")

def log_matched_files(trace_id, matched, unmatched):
    logger.info(f"[{trace_id}] Matched {len(matched)} files, Unmatched: {len(unmatched)}")
    if len(matched) < 10:
        logger.info(f"[{trace_id}] Files: {matched}")

def log_checksum_ok(trace_id, filename, checksum):
    logger.info(f"[{trace_id}] [CHECKSUM OK] {filename}: {checksum}")

def log_checksum_fail(trace_id, filename, before, after):
    logger.warning(f"[{trace_id}] [CHECKSUM FAIL] {filename}: before {before} != after {after}")

def log_file_transferred(trace_id, filename, dest, duration_s):
    logger.info(f"[{trace_id}] {filename} transferred to {dest} in {duration_s:.2f}s")

def log_archive(trace_id, filename, s3_key):
    logger.info(f"[{trace_id}] Archived {filename} to S3 at {s3_key}")

def log_tmp_usage(trace_id, num_files, free_mb):
    logger.info(f"[{trace_id}] Temp usage: {num_files} files, Free: {free_mb} MB")

def log_error(trace_id, message, exc=None):
    msg = f"[{trace_id}] ERROR: {message}"
    if exc:
        msg += f" Exception: {exc}"
    logger.error(msg)

def log_warning(trace_id, message):
    logger.warning(f"[{trace_id}] WARNING: {message}")

def log_box_version(trace_id, filename, box_id, version):
    logger.info(f"[{trace_id}] {filename} uploaded to Box (ID: {box_id}, Version: {version})")


# ---- Any other custom log helpers as you need ----

