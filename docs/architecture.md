# PhishGuard Architecture

## Detection Pipeline

```
INPUT (raw email or URL)
        │
        ▼
┌─────────────────┐
│  PREPROCESSOR   │  Detect mode, parse headers/body/URLs,
│                 │  normalize domains, generate SHA256 cache key
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  REDIS CACHE    │  Key: SHA256(input)
│  CHECK          │  HIT → return cached result instantly
└────────┬────────┘  MISS → proceed to layers
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 1 — Local  (<10ms, no network)                   │
│  Homoglyph detector │ URL entropy │ IP-in-URL           │
│  Urgency keywords   │ Anchor/href mismatch              │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 2 — DNS/Network  (<300ms)                        │
│  SPF/DKIM/DMARC │ MX records │ WHOIS domain age        │
│  TLS cert age   │ rapidfuzz similarity │ Header checks  │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 3 — External APIs  (<1500ms, asyncio.gather)     │
│  Google Safe Browsing │ VirusTotal │ AbuseIPDB          │
│  Tranco rank (local file, zero latency)                 │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  LAYER 4 — Deep Analysis  (<8s, optional)               │
│  httpx redirect chain │ HTML DOM analysis               │
│  Playwright headless render (subprocess-sandboxed)      │
└────────┬────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│ RISK AGGREGATOR │  Weighted flags → 0-100 score
│                 │  Hard floor on CRITICAL → min 70
│                 │  Top-3 human-readable reasons
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ REDIS WRITE +   │  Cache with TTL by verdict
│ AUDIT LOG       │  Write to PostgreSQL always
└────────┬────────┘
         │
         ▼
     JSON RESPONSE
{ score, verdict, flags, reasons, duration_ms, cache_hit }
```

## Scoring Formula

```
raw_score = Σ (base_score × confidence) for each flag
normalized = round(100 × (1 - e^(-raw_score / 80)))
if any CRITICAL flag: normalized = max(normalized, 70)
```

## Verdict Thresholds

| Score  | Verdict      | Action              |
|--------|--------------|---------------------|
| 0–34   | LIKELY SAFE  | Allow               |
| 35–64  | SUSPICIOUS   | Warn user           |
| 65–100 | PHISHING     | Block immediately   |
| CRITICAL flag | PHISHING (floor 70) | Override |

## Redis Key Strategy

| Pattern              | TTL      |
|----------------------|----------|
| email:{sha256}       | 6 hours  |
| url:phishing:{sha256}| 24 hours |
| url:safe:{sha256}    | 1 hour   |
| whois:{domain}       | 48 hours |
| vt:{sha256}          | 24 hours |

## API Endpoints

| Method | Endpoint            | Description              |
|--------|---------------------|--------------------------|
| POST   | /analyze/email      | Analyze raw email        |
| POST   | /analyze/url        | Analyze URL              |
| GET    | /health             | System health check      |
| GET    | /cache/stats        | Redis hit/miss stats     |
| GET    | /docs               | Swagger UI               |
