# Backend Server Setup — Read This Before Touching the Backend

This is the reference for how the FastAPI backend actually runs. It exists because
the setup has been broken by mistake more than once (wrong CORS origins, missing
`.env`, stale ngrok URL, port conflicts). If you're Claude Code working on this repo,
read this file first, and update it if you change how anything runs.

---

## The stack, in one picture

```
Browser (Lovable frontend, siteguard-trust.lovable.app)
        │  HTTPS, header: ngrok-skip-browser-warning: true
        ▼
   ngrok tunnel  (public URL, changes every session on free tier)
        │
        ▼
   api  container  —  FastAPI on :8000  (backend/main.py)
        │
        ▼
   db   container  —  Postgres 16 on :5432
```

Everything backend-related runs via **Docker Compose** from `/home/user/app`.
There is no "just run uvicorn locally" path expected to work — `DATABASE_URL`
in `docker-compose.yml` points at the `db` service hostname (`db`), not
`localhost`, so running `main.py` outside Docker requires overriding
`DATABASE_URL` yourself (see `.env.example`).

---

## Starting the backend

```bash
cd /home/user/app
docker-compose up            # foreground, logs visible
# or
docker-compose up -d         # detached
```

Services started:

| Service    | Port | What it is                                   |
|------------|------|-----------------------------------------------|
| `api`      | 8000 | FastAPI backend (`backend/`)                  |
| `db`       | 5432 | Postgres 16, data in `postgres_data` volume    |
| `frontend` | 3000 | Next.js dev server — secondary, not the real frontend |

The **real frontend is the separate Lovable repo** (`russell1298/siteguard-trust`),
not the `frontend/` folder in this repo. Don't confuse the two.

### After changing `.env`

```bash
docker-compose down
docker-compose up
```

Env vars are read at container start — editing `.env` alone does nothing until
you restart.

### After changing `backend/Dockerfile` or `backend/requirements.txt`

```bash
docker-compose up --build
```

`backend/` is bind-mounted into the `api` container for live reload
(`uvicorn --reload`), so plain Python edits under `backend/` are picked up
without a rebuild. Dependency or system-package changes need `--build`.

---

## `.env` (backend) — required, gitignored

Copy `.env.example` → `.env` and fill in real values. **This file must never be
committed.** Key vars:

- `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` — used by both `db` and `api`
- `ALLOWED_ORIGINS` — comma-separated CORS allowlist. Must include the Lovable
  frontend URL and `localhost` dev ports, or the browser will get CORS errors.
- `SUPABASE_JWT_SECRET` — verifies logged-in users
- `OWNER_EMAIL` — the account that bypasses scan rate limits
- Stripe / Resend keys — only needed once those integrations are wired up

If the API container won't start or the frontend can't reach it, **check `.env`
exists and `ALLOWED_ORIGINS` is correct** before anything else.

---

## Exposing the backend to the Lovable frontend via ngrok

The Lovable frontend is hosted remotely and can't reach `localhost:8000`
directly, so a tunnel is required:

```bash
ngrok http 8000
```

This prints a URL like `https://xxxx.ngrok-free.app`. It **changes every time
ngrok is restarted** (free tier has no static domain). When it changes:

1. Update `VITE_API_URL` in `frontend-lovable/.env` to the new ngrok URL
2. Commit and push that file to `russell1298/siteguard-trust` (`main` branch)
3. Lovable redeploys automatically within ~1 minute

**If scans fail from the live frontend, the ngrok URL is stale — check this
first.**

### Required header on every frontend fetch call

ngrok's free tier serves an interstitial warning page to unrecognized clients,
which returns HTML instead of JSON and breaks the API response (and breaks
CORS preflight `OPTIONS` requests, returning 400). Every fetch to the backend
from `frontend-lovable/` must include:

```js
headers: {
  "Content-Type": "application/json",
  "ngrok-skip-browser-warning": "true",
}
```

Missing this header is the #1 cause of "scan just hangs / fails silently"
reports from the live site.

---

## Branches

- Backend dev branch (this repo, `russell1298/app`): check with
  `git branch --show-current` — it changes per session/task. Don't assume it's
  `main`. Never push backend changes to `main` directly.
- Frontend dev branch (`russell1298/siteguard-trust`): `main` — Lovable
  auto-deploys straight from it, so a bad push there goes live.

---

## Common ways this gets broken (and how to avoid it)

1. **Editing `ALLOWED_ORIGINS` and forgetting to restart Docker.** Env changes
   need `docker-compose down && docker-compose up`.
2. **Forgetting the ngrok header in a new/edited fetch call** in the Lovable
   frontend — causes silent CORS/JSON failures.
3. **Letting the ngrok URL go stale** after a restart — frontend keeps
   pointing at a dead tunnel.
4. **Committing `.env`.** It's gitignored for a reason — real DB credentials
   and (once added) Stripe/Resend secrets live there.
5. **Assuming `DATABASE_URL=localhost`.** Inside Docker Compose the Postgres
   hostname is `db`, not `localhost`. Only override to `localhost` if running
   the API outside Docker entirely.
6. **Running `uvicorn` directly without Docker** and expecting it to just
   work — it won't have Postgres reachable unless `DATABASE_URL` is manually
   pointed at a running Postgres instance.

---

## Quick health check

```bash
curl http://localhost:8000/docs   # FastAPI auto docs — confirms api container is up
docker-compose ps                 # confirms all 3 services are running/healthy
docker-compose logs api --tail 50 # recent backend logs
```
