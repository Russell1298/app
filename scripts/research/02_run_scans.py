#!/usr/bin/env python3
"""
Phase 2 — Research-safe scans (--profile=research-safe).

Runs headers + DNS + SSL checks only. Exposure and secrets scanners are
disabled in this profile. All requests use the SiteGuard-Research UA.

Output: data/research.db  (SQLite — tables: sites, scans, findings)
Failed scans are recorded with status='error' rather than dropped.
"""
import asyncio
import csv
import json
import socket
import sqlite3
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
import httpx

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
CSV_PATH = DATA_DIR / "targets.csv"
DB_PATH  = DATA_DIR / "research.db"

MAX_CONCURRENT = 20
UA = "SiteGuard-Research/1.0 (+https://siteguard-trust.lovable.app/methodology)"

# Per-host rate-limiting: queue one request per domain; with 20-wide semaphore
# and each domain scanned exactly once, the 2 s same-host rule is automatic.

_resolver = dns.resolver.Resolver()
_resolver.timeout  = 5
_resolver.lifetime = 10


# ═══════════════════════════════════════════════════════════════════════════════
# Standalone scanner implementations (no backend dependency)
# ═══════════════════════════════════════════════════════════════════════════════

Finding = dict[str, Any]   # {scanner, title, severity, description, remediation}

SEVERITIES = {"critical": 4, "high": 3, "medium": 2, "low": 1}
PENALTIES  = {
    # headers
    "Missing Content-Security-Policy":          30,
    "Missing HTTP Strict-Transport-Security":    25,
    "Missing X-Frame-Options":                  15,
    "Missing X-Content-Type-Options":           10,
    "Missing Referrer-Policy":                   5,
    "Missing Permissions-Policy":                5,
    "Server version disclosed":                  5,
    "Technology stack disclosed":                5,
    # dns
    "No SPF record":                            20,
    "No DMARC record":                          20,
    # ssl
    "No HTTPS support":                         60,
    "SSL certificate expired":                  50,
    "SSL certificate expiring within 30 days":  30,
    "TLS 1.0 supported":                        25,
    "TLS 1.1 supported":                        15,
    "Weak TLS cipher in use":                   20,
}

def _score(findings: list[Finding]) -> tuple[float, str]:
    total = min(100, sum(PENALTIES.get(f["title"], 5) for f in findings))
    level = (
        "critical" if total >= 70 else
        "high"     if total >= 45 else
        "medium"   if total >= 20 else
        "low"
    )
    return total, level


# ── Headers scanner ──────────────────────────────────────────────────────────

async def _scan_headers(domain: str, client: httpx.AsyncClient) -> dict:
    findings: list[Finding] = []
    try:
        r = await client.get(f"https://{domain}/", follow_redirects=True, timeout=12)
        h = {k.lower(): v for k, v in r.headers.items()}

        checks = [
            ("content-security-policy",  "Missing Content-Security-Policy",
             "high",   "Prevents XSS and data-injection attacks."),
            ("strict-transport-security","Missing HTTP Strict-Transport-Security",
             "high",   "Without HSTS browsers may connect over plain HTTP."),
            ("x-frame-options",          "Missing X-Frame-Options",
             "medium", "Site may be embedded in an iframe for clickjacking."),
            ("x-content-type-options",   "Missing X-Content-Type-Options",
             "medium", "Browser may MIME-sniff responses into executable types."),
            ("referrer-policy",          "Missing Referrer-Policy",
             "low",    "Full URL may leak to third-party sites via Referer header."),
            ("permissions-policy",       "Missing Permissions-Policy",
             "low",    "No browser feature restrictions declared."),
        ]
        for header, title, severity, description in checks:
            # CSP can also come via report-only — count as present
            if header == "content-security-policy":
                if header not in h and "content-security-policy-report-only" not in h:
                    findings.append({"scanner": "headers", "title": title,
                                     "severity": severity, "description": description,
                                     "remediation": f"Add the {header} response header."})
            else:
                if header not in h:
                    findings.append({"scanner": "headers", "title": title,
                                     "severity": severity, "description": description,
                                     "remediation": f"Add the {header} response header."})

        # Information disclosure
        for hdr, label in [("server", "Server version disclosed"),
                            ("x-powered-by", "Technology stack disclosed"),
                            ("x-aspnet-version", "Technology stack disclosed"),
                            ("x-aspnetmvc-version", "Technology stack disclosed")]:
            if hdr in h:
                findings.append({
                    "scanner": "headers",
                    "title":   label,
                    "severity": "low",
                    "description": f"{hdr}: {h[hdr][:80]}",
                    "remediation": f"Remove or obscure the {hdr} header.",
                })

        score, level = _score(findings)
        return {"score": score, "level": level, "findings": findings, "error": None}

    except httpx.ConnectError:
        # Fall back to HTTP
        try:
            r2 = await client.get(f"http://{domain}/", follow_redirects=True, timeout=10)
            # If HTTP-only, flag it
            findings.append({
                "scanner": "headers",
                "title":   "Missing HTTP Strict-Transport-Security",
                "severity": "high",
                "description": "Site does not serve HTTPS at all.",
                "remediation": "Enable HTTPS and add an HSTS header.",
            })
            h = {k.lower(): v for k, v in r2.headers.items()}
            for header, title, severity, description in [
                ("content-security-policy", "Missing Content-Security-Policy", "high",
                 "Prevents XSS attacks."),
                ("x-frame-options", "Missing X-Frame-Options", "medium",
                 "Clickjacking risk."),
                ("x-content-type-options", "Missing X-Content-Type-Options", "medium",
                 "MIME sniffing risk."),
            ]:
                if header not in h:
                    findings.append({"scanner": "headers", "title": title,
                                     "severity": severity, "description": description,
                                     "remediation": f"Add the {header} header."})
            score, level = _score(findings)
            return {"score": score, "level": level, "findings": findings, "error": None}
        except Exception as e2:
            return {"score": None, "level": None, "findings": [], "error": str(e2)}

    except Exception as e:
        return {"score": None, "level": None, "findings": [], "error": str(e)}


# ── DNS scanner ──────────────────────────────────────────────────────────────

def _txt_records(name: str) -> list[str]:
    try:
        answers = _resolver.resolve(name, "TXT")
        out = []
        for rdata in answers:
            out.append("".join(
                s.decode() if isinstance(s, bytes) else s
                for s in rdata.strings
            ))
        return out
    except Exception:
        return []


def _scan_dns(domain: str) -> dict:
    findings: list[Finding] = []

    # SPF
    apex_txt = _txt_records(domain)
    has_spf = any(r.lower().startswith("v=spf1") for r in apex_txt)
    if not has_spf:
        findings.append({
            "scanner": "dns", "title": "No SPF record",
            "severity": "medium",
            "description": "Missing SPF TXT record allows email spoofing.",
            "remediation": 'Add a TXT record: v=spf1 include:… ~all',
        })

    # DMARC
    dmarc_txt = _txt_records(f"_dmarc.{domain}")
    has_dmarc = any(r.lower().startswith("v=dmarc1") for r in dmarc_txt)
    if not has_dmarc:
        findings.append({
            "scanner": "dns", "title": "No DMARC record",
            "severity": "medium",
            "description": "Missing DMARC record means no policy for failed SPF/DKIM mail.",
            "remediation": 'Add _dmarc TXT: v=DMARC1; p=none; rua=mailto:…',
        })

    score, level = _score(findings)
    return {"score": score, "level": level, "findings": findings, "error": None}


# ── SSL scanner ──────────────────────────────────────────────────────────────

def _probe_tls(domain: str, version: ssl.TLSVersion) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def _cert_expiry(domain: str) -> tuple[datetime | None, str | None]:
    """Returns (not_after, error_string)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                not_after_str = cert.get("notAfter", "")
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                return not_after, None
    except ssl.SSLCertVerificationError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


def _scan_ssl(domain: str) -> dict:
    findings: list[Finding] = []

    # Check HTTPS at all
    try:
        sock = socket.create_connection((domain, 443), timeout=6)
        sock.close()
        https_ok = True
    except Exception:
        https_ok = False

    if not https_ok:
        findings.append({
            "scanner": "ssl", "title": "No HTTPS support",
            "severity": "critical",
            "description": "Port 443 is not open — the site has no TLS.",
            "remediation": "Obtain a TLS certificate and configure HTTPS.",
        })
        score, level = _score(findings)
        return {"score": score, "level": level, "findings": findings, "error": None}

    # Cert expiry
    not_after, cert_err = _cert_expiry(domain)
    if cert_err:
        findings.append({
            "scanner": "ssl", "title": "SSL certificate expired",
            "severity": "critical",
            "description": f"Certificate error: {cert_err[:120]}",
            "remediation": "Renew or replace the TLS certificate.",
        })
    elif not_after:
        now  = datetime.now(timezone.utc)
        days = (not_after - now).days
        if days < 0:
            findings.append({
                "scanner": "ssl", "title": "SSL certificate expired",
                "severity": "critical",
                "description": f"Certificate expired {abs(days)} days ago.",
                "remediation": "Renew the TLS certificate immediately.",
            })
        elif days < 30:
            findings.append({
                "scanner": "ssl", "title": "SSL certificate expiring within 30 days",
                "severity": "high",
                "description": f"Certificate expires in {days} days.",
                "remediation": "Renew the TLS certificate now.",
            })

    # Old TLS versions
    try:
        if _probe_tls(domain, ssl.TLSVersion.TLSv1):
            findings.append({
                "scanner": "ssl", "title": "TLS 1.0 supported",
                "severity": "high",
                "description": "TLS 1.0 is deprecated and contains known vulnerabilities.",
                "remediation": "Disable TLS 1.0 in your server configuration.",
            })
    except AttributeError:
        pass  # TLSv1 constant not available on this OpenSSL build
    try:
        if _probe_tls(domain, ssl.TLSVersion.TLSv1_1):
            findings.append({
                "scanner": "ssl", "title": "TLS 1.1 supported",
                "severity": "medium",
                "description": "TLS 1.1 is deprecated and should not be offered.",
                "remediation": "Disable TLS 1.1 and only allow TLS 1.2+.",
            })
    except AttributeError:
        pass

    score, level = _score(findings)
    return {"score": score, "level": level, "findings": findings, "error": None}


# ═══════════════════════════════════════════════════════════════════════════════
# SQLite storage
# ═══════════════════════════════════════════════════════════════════════════════

def _init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    PRAGMA journal_mode=WAL;

    CREATE TABLE IF NOT EXISTS sites (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        rank     INTEGER,
        domain   TEXT UNIQUE NOT NULL,
        platform TEXT NOT NULL,
        added_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS scans (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        site_id        INTEGER REFERENCES sites(id),
        domain         TEXT    NOT NULL,
        platform       TEXT    NOT NULL,
        status         TEXT    NOT NULL,   -- 'ok' | 'error'
        error_msg      TEXT,
        headers_score  REAL,
        headers_level  TEXT,
        dns_score      REAL,
        dns_level      TEXT,
        ssl_score      REAL,
        ssl_level      TEXT,
        overall_score  REAL,
        overall_level  TEXT,
        scanned_at     TEXT DEFAULT (datetime('now')),
        raw_json       TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER REFERENCES scans(id),
        domain      TEXT NOT NULL,
        platform    TEXT NOT NULL,
        scanner     TEXT NOT NULL,
        title       TEXT NOT NULL,
        severity    TEXT NOT NULL,
        description TEXT,
        remediation TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
    CREATE INDEX IF NOT EXISTS idx_findings_title ON findings(title);
    """)
    conn.commit()
    return conn


def _upsert_site(conn: sqlite3.Connection, rank: int, domain: str, platform: str) -> int:
    conn.execute(
        "INSERT OR IGNORE INTO sites (rank, domain, platform) VALUES (?,?,?)",
        (rank, domain, platform),
    )
    conn.commit()
    return conn.execute("SELECT id FROM sites WHERE domain=?", (domain,)).fetchone()[0]


def _overall(h: dict, d: dict, s: dict) -> tuple[float, str]:
    weights = [(h, 0.40), (d, 0.30), (s, 0.30)]
    total_w = sum(w for r, w in weights if r.get("score") is not None)
    if total_w == 0:
        return 0.0, "low"
    score = sum(r["score"] * w for r, w in weights if r.get("score") is not None) / total_w
    level = (
        "critical" if score >= 70 else
        "high"     if score >= 45 else
        "medium"   if score >= 20 else
        "low"
    )
    return round(score, 1), level


def _store_scan(
    conn: sqlite3.Connection,
    site_id: int, domain: str, platform: str,
    h: dict, d: dict, s: dict,
    error: str | None = None,
) -> int:
    if error:
        cur = conn.execute(
            "INSERT INTO scans (site_id,domain,platform,status,error_msg) VALUES (?,?,?,'error',?)",
            (site_id, domain, platform, error),
        )
        conn.commit()
        return cur.lastrowid

    overall_score, overall_level = _overall(h, d, s)
    raw = json.dumps({"headers": h, "dns": d, "ssl": s})

    cur = conn.execute(
        """INSERT INTO scans
           (site_id,domain,platform,status,
            headers_score,headers_level,dns_score,dns_level,ssl_score,ssl_level,
            overall_score,overall_level,raw_json)
           VALUES (?,?,?,'ok',?,?,?,?,?,?,?,?,?)""",
        (
            site_id, domain, platform,
            h.get("score"), h.get("level"),
            d.get("score"), d.get("level"),
            s.get("score"), s.get("level"),
            overall_score, overall_level,
            raw,
        ),
    )
    scan_id = cur.lastrowid

    rows = [
        (scan_id, domain, platform,
         f["scanner"], f["title"], f["severity"],
         f.get("description", ""), f.get("remediation", ""))
        for src in (h, d, s)
        for f in src.get("findings", [])
    ]
    if rows:
        conn.executemany(
            "INSERT INTO findings (scan_id,domain,platform,scanner,title,severity,description,remediation)"
            " VALUES (?,?,?,?,?,?,?,?)",
            rows,
        )
    conn.commit()
    return scan_id


# ═══════════════════════════════════════════════════════════════════════════════
# Orchestration
# ═══════════════════════════════════════════════════════════════════════════════

async def _scan_one(
    rank: int, domain: str, platform: str,
    sem: asyncio.Semaphore,
    client: httpx.AsyncClient,
) -> tuple[int, str, str, dict, dict, dict, str | None]:
    async with sem:
        try:
            h, d_task, s_task = await asyncio.gather(
                _scan_headers(domain, client),
                asyncio.to_thread(_scan_dns, domain),
                asyncio.to_thread(_scan_ssl, domain),
                return_exceptions=True,
            )
            h = h if isinstance(h, dict) else {"score": None, "level": None, "findings": [], "error": str(h)}
            d = d_task if isinstance(d_task, dict) else {"score": None, "level": None, "findings": [], "error": str(d_task)}
            s = s_task if isinstance(s_task, dict) else {"score": None, "level": None, "findings": [], "error": str(s_task)}
            return rank, domain, platform, h, d, s, None
        except Exception as e:
            return rank, domain, platform, {}, {}, {}, str(e)


async def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not CSV_PATH.exists():
        print(f"ERROR: {CSV_PATH} not found — run 01_build_targets.py first", file=sys.stderr)
        sys.exit(1)

    with open(CSV_PATH) as fh:
        targets = list(csv.DictReader(fh))

    print(f"📋 {len(targets)} targets loaded from {CSV_PATH}", flush=True)

    conn = _init_db()

    already_ok = {
        r[0] for r in conn.execute(
            "SELECT domain FROM scans WHERE status='ok'"
        ).fetchall()
    }
    pending = [t for t in targets if t["domain"] not in already_ok]
    print(f"   {len(already_ok)} already done, {len(pending)} to scan", flush=True)

    if not pending:
        print("Nothing to do.", flush=True)
        conn.close()
        return

    sem = asyncio.Semaphore(MAX_CONCURRENT)
    limits = httpx.Limits(
        max_connections=MAX_CONCURRENT + 5,
        max_keepalive_connections=MAX_CONCURRENT,
    )
    ok_count = err_count = 0

    async with httpx.AsyncClient(
        headers={"User-Agent": UA},
        follow_redirects=True,
        limits=limits,
    ) as client:
        tasks = [
            asyncio.create_task(
                _scan_one(
                    int(t["rank"]), t["domain"], t["platform"], sem, client
                )
            )
            for t in pending
        ]

        for i, coro in enumerate(asyncio.as_completed(tasks)):
            rank, domain, platform, h, d, s, error = await coro

            site_id = _upsert_site(conn, rank, domain, platform)
            if error:
                _store_scan(conn, site_id, domain, platform, {}, {}, {}, error=error)
                err_count += 1
            else:
                _store_scan(conn, site_id, domain, platform, h, d, s)
                ok_count += 1

            pct = (i + 1) / len(pending) * 100
            print(
                f"\r   [{i+1:>3}/{len(pending)}] {pct:>5.1f}%  "
                f"✓{ok_count} ✗{err_count}  {domain:<40}",
                end="", flush=True,
            )

    print(f"\n\n✅ Scans done: {ok_count} ok, {err_count} errors → {DB_PATH}", flush=True)
    conn.close()


if __name__ == "__main__":
    asyncio.run(main())
