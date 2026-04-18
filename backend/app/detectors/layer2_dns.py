"""
Layer 2 — DNS / Network Detectors (< 300ms)
"""
import asyncio
import ssl
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Optional
import re

import dns.asyncresolver
import dns.exception
import whois
from rapidfuzz import fuzz

from app.models.schemas import Flag, Severity, AnalysisContext
from app.core.config import get_settings
from app.core.redis_client import cache_get, cache_set, TTL_WHOIS

settings = get_settings()

KNOWN_BRANDS = [
    "google", "microsoft", "apple", "amazon", "paypal", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox",
    "github", "outlook", "office365", "gmail", "yahoo", "bing",
    "icloud", "chase", "wellsfargo", "bankofamerica", "citibank",
    "irs", "fedex", "ups", "dhl", "usps",
]

# ============================================================
# TYPOSQUATTING DETECTION
# ============================================================

TYPO_MAP = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "@": "a", "$": "s", "!": "i",
}


def normalize_typo(text: str) -> str:
    """Convert common typosquatting characters to normal letters."""
    result = text.lower()
    for typo, normal in TYPO_MAP.items():
        result = result.replace(typo, normal)
    return result


def check_typosquatting(domain: str) -> Flag:
    """Detect typosquatting like amaz0n, paypa1, micr0s0ft."""
    if not domain:
        return Flag(type="NO_TYPOSQUATTING", severity=Severity.NONE, score=0, source="similarity")
    
    domain_clean = domain.split(".")[0].lower()
    normalized = normalize_typo(domain_clean)
    
    for brand in KNOWN_BRANDS:
        if brand == domain_clean:
            continue
        if brand in normalized:
            return Flag(
                type="TYPO_SQUATTING",
                severity=Severity.HIGH,
                score=30,
                detail=f"Domain '{domain}' contains typosquatting of brand '{brand}'",
                source="similarity",
            )
        # Also check fuzzy ratio on normalized name
        score = fuzz.ratio(normalized, brand)
        if score >= 85:
            return Flag(
                type="TYPO_SQUATTING",
                severity=Severity.HIGH,
                score=30,
                detail=f"Domain '{domain}' is {score}% similar to brand '{brand}' after normalization",
                source="similarity",
            )
    return Flag(type="NO_TYPOSQUATTING", severity=Severity.NONE, score=0, source="similarity")


def check_suspicious_tld_for_domain(domain: str) -> Flag:
    """Flag suspicious TLDs in domains (used for email sender domains)."""
    if not domain:
        return Flag(type="TLD_OK", severity=Severity.NONE, score=0, source="dns")
    
    SUSPICIOUS_TLDS = {
        "xyz", "top", "click", "link", "work", "date", "men",
        "club", "online", "live", "site", "tech", "review", "trade",
        "download", "bid", "loan", "win", "stream", "party", "gq", "ml", "tk"
    }
    
    parts = domain.split(".")
    tld = parts[-1].lower() if len(parts) > 1 else ""
    
    if tld in SUSPICIOUS_TLDS:
        return Flag(
            type="SUSPICIOUS_TLD",
            severity=Severity.MEDIUM,
            score=15,
            detail=f"Sender domain uses suspicious TLD '.{tld}' commonly used in phishing",
            source="dns",
        )
    return Flag(type="TLD_OK", severity=Severity.NONE, score=0, source="dns")


async def check_spf_dmarc(domain: str) -> list[Flag]:
    flags = []
    try:
        import checkdmarc
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(None, checkdmarc.check_domains, [domain])

        if results:
            r = results[0]
            spf = r.get("spf", {})
            dmarc = r.get("dmarc", {})

            if not spf.get("valid"):
                flags.append(Flag(
                    type="NO_SPF_RECORD",
                    severity=Severity.HIGH,
                    score=20,
                    detail=f"SPF record missing or invalid for {domain}",
                    source="dns",
                ))

            if not dmarc.get("valid"):
                flags.append(Flag(
                    type="NO_DMARC_RECORD",
                    severity=Severity.MEDIUM,
                    score=18,
                    detail=f"DMARC record missing or invalid for {domain}",
                    source="dns",
                ))
    except Exception:
        pass
    return flags


async def check_mx_record(domain: str) -> Flag:
    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(domain, "MX")
        if not answers:
            return Flag(
                type="NO_MX_RECORD",
                severity=Severity.MEDIUM,
                score=10,
                detail=f"No MX records found for {domain}",
                source="dns",
            )
        return Flag(type="MX_RECORD_OK", severity=Severity.NONE, score=0, source="dns")
    except dns.exception.NXDOMAIN:
        return Flag(
            type="NO_MX_RECORD",
            severity=Severity.MEDIUM,
            score=10,
            detail=f"Domain {domain} does not exist (NXDOMAIN)",
            source="dns",
        )
    except Exception:
        return Flag(type="MX_CHECK_SKIPPED", severity=Severity.NONE, score=0, source="dns")


async def check_domain_age(domain: str) -> Flag:
    cache_key = f"whois:{domain}"
    cached = await cache_get(cache_key)
    if cached:
        return Flag(**cached)

    try:
        loop = asyncio.get_event_loop()
        info = await asyncio.wait_for(
            loop.run_in_executor(None, whois.whois, domain),
            timeout=10.0,
        )

        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            flag = Flag(
                type="WHOIS_UNAVAILABLE",
                severity=Severity.MEDIUM,
                score=15,
                detail=f"WHOIS creation date unavailable for {domain}",
                source="whois",
            )
        else:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation_date).days

            if age_days < 30:
                flag = Flag(
                    type="VERY_NEW_DOMAIN",
                    severity=Severity.HIGH,
                    score=30,
                    detail=f"Domain created only {age_days} days ago",
                    source="whois",
                )
            elif age_days < 90:
                flag = Flag(
                    type="NEW_DOMAIN",
                    severity=Severity.MEDIUM,
                    score=18,
                    detail=f"Domain created {age_days} days ago",
                    source="whois",
                )
            else:
                flag = Flag(type="DOMAIN_AGE_OK", severity=Severity.NONE, score=0, source="whois")

    except asyncio.TimeoutError:
        flag = Flag(
            type="WHOIS_UNAVAILABLE",
            severity=Severity.MEDIUM,
            score=15,
            detail="WHOIS lookup timed out",
            source="whois",
        )
    except Exception as e:
        flag = Flag(
            type="WHOIS_UNAVAILABLE",
            severity=Severity.MEDIUM,
            score=15,
            detail=f"WHOIS error: {str(e)[:60]}",
            source="whois",
        )

    await cache_set(cache_key, flag.dict(), TTL_WHOIS)
    return flag


async def check_tls_cert(domain: str) -> Flag:
    """Check TLS certificate age."""
    try:
        loop = asyncio.get_event_loop()

        def _get_cert():
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((domain, 443), timeout=5),
                server_hostname=domain,
            ) as s:
                return s.getpeercert()

        cert = await asyncio.wait_for(
            loop.run_in_executor(None, _get_cert),
            timeout=8.0,
        )

        not_before_str = cert.get("notBefore", "")
        if not_before_str:
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            not_before = not_before.replace(tzinfo=timezone.utc)
            cert_age_days = (datetime.now(timezone.utc) - not_before).days

            if cert_age_days < 30:
                return Flag(
                    type="YOUNG_TLS_CERT",
                    severity=Severity.MEDIUM,
                    score=12,
                    detail=f"TLS cert issued only {cert_age_days} days ago",
                    source="tls",
                )

        return Flag(type="TLS_CERT_OK", severity=Severity.NONE, score=0, source="tls")

    except Exception:
        return Flag(
            type="TLS_CHECK_FAILED",
            severity=Severity.LOW,
            score=5,
            detail="TLS certificate check failed (no HTTPS or invalid cert)",
            source="tls",
        )


def check_lookalike_domain(domain: str) -> Flag:
    """Check for lookalike domains using fuzzy matching."""
    if not domain:
        return Flag(type="DOMAIN_OK", severity=Severity.NONE, score=0, source="similarity")
    
    base = domain.rsplit(".", 2)[-2] if domain.count(".") >= 2 else domain.split(".")[0]
    base_clean = normalize_typo(base)

    for brand in KNOWN_BRANDS:
        if base == brand:
            continue
        score = fuzz.ratio(base_clean, brand)
        if score >= 85:
            return Flag(
                type="LOOKALIKE_DOMAIN",
                severity=Severity.HIGH,
                score=25,
                detail=f"Domain '{domain}' is {score}% similar to brand '{brand}'",
                source="similarity",
            )
    return Flag(type="DOMAIN_OK", severity=Severity.NONE, score=0, source="similarity")


def _extract_email_domain(header_value: str) -> str:
    if not header_value:
        return ""
    match = re.search(r"@([\w.\-]+)", header_value)
    return match.group(1).lower() if match else ""


def check_header_mismatches(headers: dict) -> list[Flag]:
    flags = []
    from_domain = _extract_email_domain(headers.get("From", ""))
    reply_domain = _extract_email_domain(headers.get("Reply-To", ""))
    return_domain = _extract_email_domain(headers.get("Return-Path", ""))

    if reply_domain and reply_domain != from_domain:
        flags.append(Flag(
            type="REPLY_TO_MISMATCH",
            severity=Severity.HIGH,
            score=25,
            detail=f"From: {from_domain} but Reply-To: {reply_domain}",
            source="headers",
        ))

    if return_domain and return_domain != from_domain:
        flags.append(Flag(
            type="RETURN_PATH_MISMATCH",
            severity=Severity.MEDIUM,
            score=15,
            detail=f"From: {from_domain} but Return-Path: {return_domain}",
            source="headers",
        ))

    return flags


def check_sender_link_mismatch(sender_domain: str, urls: list[str]) -> Flag:
    """Check if email claims to be from one domain but links to another."""
    if not sender_domain or not urls:
        return Flag(type="NO_MISMATCH_CHECK", severity=Severity.NONE, score=0, source="headers")
    
    sender_clean = sender_domain.lower().replace("www.", "")
    sender_brand = sender_clean.split(".")[0]
    
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            url_domain = parsed.netloc.lower().split(":")[0]
            
            if not url_domain:
                continue
                
            url_clean = url_domain.lower().replace("www.", "")
            
            if sender_clean != url_clean:
                if sender_brand not in url_clean:
                    return Flag(
                        type="BRAND_IMPERSONATION",
                        severity=Severity.CRITICAL,
                        score=40,
                        detail=f"Email from {sender_domain} contains link to {url_domain}",
                        source="headers",
                    )
                elif sender_clean not in url_clean and url_clean not in sender_clean:
                    return Flag(
                        type="SENDER_LINK_MISMATCH",
                        severity=Severity.HIGH,
                        score=30,
                        detail=f"Email from {sender_domain} links to {url_domain}",
                        source="headers",
                    )
        except Exception:
            continue
    
    return Flag(type="SENDER_LINK_MATCH", severity=Severity.NONE, score=0, source="headers")


async def run_layer2(ctx: AnalysisContext) -> list[Flag]:
    flags = []
    tasks = []

    for domain in ctx.domains[:3]:
        tasks.append(check_domain_age(domain))
        tasks.append(check_mx_record(domain))
        tasks.append(check_tls_cert(domain))
        flags.append(check_lookalike_domain(domain))
        # NEW: Add typosquatting check for each domain
        flags.append(check_typosquatting(domain))

    if ctx.mode == "email" and ctx.sender_domain:
        tasks.append(check_spf_dmarc(ctx.sender_domain))
        tasks.append(check_domain_age(ctx.sender_domain))
        tasks.append(check_mx_record(ctx.sender_domain))
        flags.extend(check_header_mismatches(ctx.headers))
        flags.append(check_sender_link_mismatch(ctx.sender_domain, ctx.urls))
        # NEW: Check typosquatting on sender domain
        flags.append(check_typosquatting(ctx.sender_domain))
        # NEW: Check suspicious TLD on sender domain
        flags.append(check_suspicious_tld_for_domain(ctx.sender_domain))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            flags.extend(r)
        elif isinstance(r, Flag):
            flags.append(r)

    return [f for f in flags if f is not None]