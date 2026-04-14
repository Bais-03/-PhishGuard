# PhishGuard 🛡️
> Production-Grade Phishing Detection System — Resonance 2K26, VIT Pune

## Stack
- **Backend**: Python 3.11 / FastAPI / asyncio
- **Frontend**: React 18 / Vite / Tailwind CSS
- **Cache**: Redis
- **Database**: PostgreSQL
- **Detection**: 11-layer engine (URL, Email, Content, Behavioral)

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker (for Redis + PostgreSQL)

### 1. Start Infrastructure
```bash
docker compose up -d
```

### 2. Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
cp .env.example .env            # Add your API keys
python scripts/download_tranco.py
uvicorn app.main:app --reload --port 8000
```

### 3. Frontend
```bash
cd frontend
npm install
npm run dev                     # Runs on http://localhost:5173
```

## API Keys Required
| Key | Free Tier | Get It |
|-----|-----------|--------|
| `VT_API_KEY` | 500 req/day | https://virustotal.com |
| `GOOGLE_SAFE_BROWSING_KEY` | 10k req/day | https://developers.google.com/safe-browsing |
| `ABUSEIPDB_KEY` | 1000 req/day | https://abuseipdb.com |

## Architecture
See `docs/architecture.md` for full pipeline documentation.

## Demo Day Checklist
- [ ] `docker compose up -d` → Redis + Postgres running
- [ ] `/health` endpoint returns all green
- [ ] PhishTank sample emails loaded in `tests/samples/`
- [ ] Frontend on `:5173`, backend on `:8000`
