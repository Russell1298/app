# SiteGuard — Claude Code Project Guide

## Project Overview

SiteGuard is a **defensive cybersecurity web app** for small businesses — passive website security assessment only. Users enter a URL, the backend scans it across 7 dimensions, and results are shown in a dashboard with a paid PDF export.

**Live frontend**: https://siteguard-trust.lovable.app  
**Backend (local + ngrok)**: See ngrok URL below — changes each session

---

## Security Constraints (Non-Negotiable)

- **Passive scanning only** — no exploitation, no brute forcing
- **No bypass techniques** — no offensive tooling of any kind
- **Redact secrets before storage** — never log real credentials found during scans
- Keep the product compliant and defensive at all times

---

## Two-Repo Architecture

| Repo | Purpose | Location in workspace |
|------|---------|----------------------|
| `russell1298/app` | FastAPI backend + Docker Compose | `/home/user/app` (this repo) |
| `russell1298/siteguard-trust` | Lovable frontend (React/Vite) | `/home/user/app/frontend-lovable/` |

The frontend repo is cloned as a **subfolder** of this workspace so Claude Code can read and edit it. It is a separate git repo — commits/pushes go to `russell1298/siteguard-trust`, not `russell1298/app`.

---

## Pushing Frontend Changes Live (Lovable Auto-Deploy)

When you edit files in `frontend-lovable/`, **always pull first** to get any changes Lovable may have committed, then push:

```bash
cd /home/user/app/frontend-lovable
git pull origin main
```

Then make your edits, commit, and push:

```bash
cd /home/user/app/frontend-lovable
git add <files>
git commit -m "your message"
git push origin main
```

**Lovable detects the push automatically and redeploys within ~1 minute.** No manual publish step needed.

> If asked to "push frontend changes" or "deploy to Lovable", always run git commands from `/home/user/app/frontend-lovable/` and push to `origin main`.

---

## Backend — Local Dev with Docker Compose

```bash
# Start everything (from /home/user/app)
docker-compose up

# Restart after .env changes
docker-compose down
docker-compose up

# Rebuild after Dockerfile/dependency changes
docker-compose up --build
```

Services:
- `api` → FastAPI on port 8000
- `db` → PostgreSQL 16 on port 5432
- `frontend` → Next.js dev server on port 3000 (secondary; Lovable is the main frontend)

### CORS

CORS origins are set via `ALLOWED_ORIGINS` in `.env` (never commit this file). Current value:
```
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173,https://siteguard-trust.lovable.app
```

After changing `.env`, restart Docker for the change to take effect.

---

## ngrok Tunnel

The backend runs locally and is exposed via ngrok for the Lovable frontend to reach it:

```bash
ngrok http 8000
```

The URL changes each session (free tier). When it changes:
1. Update `VITE_API_URL` in `frontend-lovable/.env`
2. Commit and push that `.env` to `russell1298/siteguard-trust`
3. Lovable will redeploy with the new URL

### CRITICAL: ngrok Browser Interstitial Header

Every API `fetch()` call in the frontend **must** include this header, or ngrok's free-tier interstitial page will intercept the request and return HTML instead of JSON:

```js
headers: {
  "Content-Type": "application/json",
  "ngrok-skip-browser-warning": "true",
}
```

Without this header, CORS preflights (OPTIONS) return 400 and scans fail.

---

## Environment Files

| File | Location | Committed? |
|------|----------|------------|
| `.env` (backend) | `/home/user/app/.env` | **NO — gitignored** |
| `.env.example` | `/home/user/app/.env.example` | Yes |
| `.env` (frontend) | `frontend-lovable/.env` | **Yes** (Lovable reads it from GitHub) |

The frontend `.env` contains only public/anon keys (Supabase publishable key, public URLs). The `siteguard-trust` repo **must stay private** since this file is committed.

---

## Backend Structure

```
backend/
  main.py          # FastAPI app, CORS config, lifespan
  api/
    routes.py      # API endpoints
  db/
    session.py     # SQLAlchemy async session, init_db, create_tables
    models.py      # ORM models
  scanners/        # 7 passive scanners (DNS, TLS, headers, etc.)
  reports/         # WeasyPrint + Jinja2 PDF generation
```

API base path: `/api/v1/`  
Main scan endpoint: `POST /api/v1/scan/full`

---

## Roadmap

- [ ] Supabase auth in FastAPI (JWT middleware, `user_id` on scan records)
- [ ] Stripe $5.99 PDF gate (checkout session + webhook + `paid` flag on scans)
- [ ] Email delivery via Resend
- [ ] Scheduled monitoring via APScheduler
- [ ] Deploy backend to VPS (replace ngrok with real domain)
- [ ] Landing page

---

## Current Dev Branch (backend)

`claude/nice-dirac-MP6aT` — push backend changes here, not to `main`.
