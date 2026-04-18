"""
Preprocessor — converts raw email string or URL into a structured AnalysisContext.
Step 1 of the pipeline: detect mode, extract all artifacts, generate cache key.
"""
import email as stdlib_email
import hashlib
import re
import base64
import quopri
from email.header import decode_header
from urllib.parse import urlparse
from app.models.schemas import AnalysisContext
import tldextract


# ============================================================
# FIXED: Improved URL regex that captures complete URLs including query parameters
# ============================================================
URL_REGEX = re.compile(
    r"https?://[^\s<>\"'{}|\\^`\[\]]+",
    re.IGNORECASE,
)


def looks_like_url(s: str) -> bool:
    s = s.strip()
    return s.startswith("http://") or s.startswith("https://")


def normalize_url(url: str) -> str:
    return url.strip().rstrip("/").lower()


def extract_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


def decode_header_value(value: str) -> str:
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return " ".join(decoded)


def extract_headers(msg) -> dict:
    headers = {}
    for key in ["From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Received"]:
        val = msg.get(key, "")
        if val:
            headers[key] = decode_header_value(val)
    return headers


def extract_sender_domain(msg) -> str:
    from_header = msg.get("From", "")
    match = re.search(r"@([\w.\-]+)", from_header)
    return match.group(1).lower() if match else ""


def extract_sender_ip_from_received(msg) -> str:
    """Extract the originating IP from the last Received header."""
    received = msg.get_all("Received") or []
    ip_pattern = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
    for header in reversed(received):
        match = ip_pattern.search(header)
        if match:
            return match.group(1)
    return ""


def extract_text_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    else:
        if msg.get_content_type() == "text/plain":
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
    return body


def extract_html_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    else:
        if msg.get_content_type() == "text/html":
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
    return body


# ============================================================
# FIXED: extract_all_urls with URL cleaning and validation
# ============================================================
def extract_all_urls(msg) -> list[str]:
    text = extract_text_body(msg) + extract_html_body(msg)
    
    # Find all URLs using regex
    raw_urls = URL_REGEX.findall(text)
    
    # Clean and validate URLs
    cleaned_urls = []
    for url in raw_urls:
        # Remove trailing punctuation that might be attached
        url = url.rstrip('.,!?;:)]}')
        
        # Ensure it starts with http:// or https://
        if url.startswith(('http://', 'https://')):
            cleaned_urls.append(url)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in cleaned_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls


def extract_attachment_info(msg) -> list[dict]:
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            disposition = part.get_content_disposition()
            if disposition in ("attachment", "inline"):
                filename = part.get_filename() or ""
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "extension": filename.rsplit(".", 1)[-1].lower() if "." in filename else "",
                })
    return attachments


async def preprocess(raw_input: str) -> AnalysisContext:
    ctx = AnalysisContext()
    ctx.raw_input = raw_input
    ctx.cache_key = hashlib.sha256(raw_input.encode()).hexdigest()

    # Check if this is a URL (direct URL analysis)
    if looks_like_url(raw_input):
        ctx.mode = "url"
        url = normalize_url(raw_input)
        ctx.urls = [url]
        ctx.domains = [extract_domain(url)]
    else:
        # This is an email - extract all content
        ctx.mode = "email"
        msg = stdlib_email.message_from_string(raw_input)
        ctx.headers = extract_headers(msg)
        ctx.body_text = extract_text_body(msg)
        ctx.body_html = extract_html_body(msg)
        ctx.urls = extract_all_urls(msg)
        ctx.domains = [extract_domain(u) for u in ctx.urls if extract_domain(u)]
        ctx.sender_domain = extract_sender_domain(msg)
        ctx.sender_ip = extract_sender_ip_from_received(msg)
        ctx.attachments = extract_attachment_info(msg)

    return ctx