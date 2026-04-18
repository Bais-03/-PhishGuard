"""
Layer 3 — External API Detectors (< 1500ms)
All called simultaneously via asyncio.gather():
- Google Safe Browsing
- VirusTotal URL/domain
- AbuseIPDB sender IP reputation
- Tranco top-1M rank (local file, zero latency)
"""
import asyncio
import httpx
import vt

from app.models.schemas import Flag, Severity, AnalysisContext
from app.core.config import get_settings
from app.core.safe_call import safe_api_call
from app.core.redis_client import cache_get, cache_set, TTL_VT, make_cache_key

settings = get_settings()

# Loaded at startup by tranco loader
TRANCO_SET: set[str] = set()


def load_tranco_into_memory(path: str) -> int:
    global TRANCO_SET
    try:
        with open(path) as f:
            for line in f:
                parts = line.strip().split(",", 1)
                if len(parts) == 2:
                    TRANCO_SET.add(parts[1].lower())
        return len(TRANCO_SET)
    except FileNotFoundError:
        return 0


# ── Google Safe Browsing ──────────────────────────────────────────

async def _check_gsb(url: str) -> dict:
    api_key = settings.google_safe_browsing_key
    if not api_key:
        return {"flags": []}

    async with httpx.AsyncClient(timeout=4.0) as client:
        resp = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json={
                "client": {"clientId": "phishguard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
        )
        data = resp.json()
        if data.get("matches"):
            threat_type = data["matches"][0].get("threatType", "THREAT")
            return {
                "flags": [Flag(
                    type="GOOGLE_SAFE_BROWSING_HIT",
                    severity=Severity.CRITICAL,
                    score=45,
                    detail=f"Google Safe Browsing: {threat_type}",
                    source="gsb",
                ).dict()]
            }
    return {"flags": []}


async def check_google_safe_browsing(url: str) -> list[Flag]:
    cache_key = make_cache_key("gsb", url)
    cached = await cache_get(cache_key)
    if cached:
        return [Flag(**f) for f in cached.get("flags", [])]

    result = await safe_api_call(lambda: _check_gsb(url), "google_safe_browsing", timeout=5.0)
    flags = [Flag(**f) for f in result.get("flags", [])]
    await cache_set(cache_key, {"flags": [f.dict() for f in flags]}, TTL_VT)
    return flags


# ── VirusTotal ────────────────────────────────────────────────────

async def _check_vt(url: str) -> dict:
    if not settings.vt_api_key:
        return {"flags": []}

    async with vt.Client(settings.vt_api_key) as client:
        url_id = vt.url_id(url)
        try:
            analysis = await client.get_object_async(f"/urls/{url_id}")
            stats = analysis.last_analysis_stats
            malicious = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            ratio = malicious / total

            if ratio > 0.10:
                return {"flags": [Flag(
                    type="VT_MALICIOUS",
                    severity=Severity.CRITICAL,
                    score=40,
                    detail=f"VirusTotal: {malicious}/{total} engines flagged this URL",
                    source="virustotal",
                ).dict()]}
            elif ratio > 0.02:
                return {"flags": [Flag(
                    type="VT_SUSPICIOUS",
                    severity=Severity.MEDIUM,
                    score=20,
                    detail=f"VirusTotal: {malicious}/{total} engines suspicious",
                    source="virustotal",
                ).dict()]}
            return {"flags": [Flag(type="VT_CLEAN", severity=Severity.NONE, score=0, source="virustotal").dict()]}

        except vt.APIError:
            await client.scan_url_async(url)
            return {"flags": [Flag(
                type="VT_NOT_FOUND",
                severity=Severity.LOW,
                score=5,
                detail="URL submitted to VirusTotal for first-time scan",
                source="virustotal",
            ).dict()]}


async def check_virustotal(url: str) -> list[Flag]:
    cache_key = make_cache_key("vt", url)
    cached = await cache_get(cache_key)
    if cached:
        return [Flag(**f) for f in cached.get("flags", [])]

    result = await safe_api_call(lambda: _check_vt(url), "virustotal", timeout=8.0)
    flags = [Flag(**f) for f in result.get("flags", [])]
    await cache_set(cache_key, {"flags": [f.dict() for f in flags]}, TTL_VT)
    return flags


# ── AbuseIPDB ─────────────────────────────────────────────────────

async def _check_abuseipdb(ip: str) -> dict:
    if not settings.abuseipdb_key or not ip:
        return {"flags": []}

    async with httpx.AsyncClient(timeout=4.0) as client:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
        )
        data = resp.json().get("data", {})
        abuse_score = data.get("abuseConfidenceScore", 0)
        if abuse_score >= 50:
            return {"flags": [Flag(
                type="ABUSEIPDB_FLAGGED",
                severity=Severity.HIGH,
                score=15,
                detail=f"Sender IP {ip} has abuse confidence score of {abuse_score}%",
                source="abuseipdb",
            ).dict()]}
    return {"flags": []}


async def check_abuseipdb(ip: str) -> list[Flag]:
    if not ip:
        return []
    cache_key = f"abuseipdb:{ip}"
    cached = await cache_get(cache_key)
    if cached:
        return [Flag(**f) for f in cached.get("flags", [])]

    result = await safe_api_call(lambda: _check_abuseipdb(ip), "abuseipdb", timeout=5.0)
    flags = [Flag(**f) for f in result.get("flags", [])]
    await cache_set(cache_key, {"flags": [f.dict() for f in flags]}, 3600)
    return flags


# ── Tranco Rank (local file, zero latency) ────────────────────────

def check_tranco(domain: str) -> Flag:
    if not domain:
        return Flag(type="TRANCO_SKIP", severity=Severity.NONE, score=0, source="tranco")
    if domain.lower() in TRANCO_SET:
        return Flag(type="IN_TRANCO", severity=Severity.NONE, score=0, source="tranco")
    return Flag(
        type="NOT_IN_TRANCO_TOP_1M",
        severity=Severity.LOW,
        score=5,
        detail=f"Domain {domain} not in Tranco top 1M",
        source="tranco",
    )


# ── Layer 3 Entrypoint ─────────────────────────────────────────────

async def run_layer3(ctx: AnalysisContext) -> list[Flag]:
    tasks = []

    for url in ctx.urls[:5]:
        tasks.append(check_google_safe_browsing(url))
        tasks.append(check_virustotal(url))

    if ctx.sender_ip:
        tasks.append(check_abuseipdb(ctx.sender_ip))

    flags = []
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            flags.extend(r)

    # Tranco is sync / local — run after gather
    for domain in ctx.domains[:5]:
        flags.append(check_tranco(domain))

    return [f for f in flags if f is not None]