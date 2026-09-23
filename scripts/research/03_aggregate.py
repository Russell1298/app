#!/usr/bin/env python3
"""
Phase 3 — Aggregate research results.

Reads data/research.db and produces data/aggregates.json with:
  - total_sites, successful_scans, failed_scans, success_rate
  - risk_distribution  (overall risk levels across all scans)
  - top_findings       (sorted by affected_percentage, with severity)
  - per_platform       (breakdown for shopify / wordpress)
  - headline_stats     (4-5 most striking findings ranked by
                        affected_percentage × severity_weight where
                        critical=4, high=3, medium=2, low=1)
"""
import json
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DB_PATH  = DATA_DIR / "research.db"
OUT_JSON = DATA_DIR / "aggregates.json"

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def main() -> None:
    if not DB_PATH.exists():
        print(f"ERROR: {DB_PATH} not found — run 02_run_scans.py first", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    # ── Basic counts ────────────────────────────────────────────────────────

    total_sites = conn.execute("SELECT COUNT(*) FROM sites").fetchone()[0]
    ok_scans    = conn.execute("SELECT COUNT(*) FROM scans WHERE status='ok'").fetchone()[0]
    err_scans   = conn.execute("SELECT COUNT(*) FROM scans WHERE status='error'").fetchone()[0]
    success_rate = round(ok_scans / total_sites * 100, 1) if total_sites else 0

    # ── Risk distribution ────────────────────────────────────────────────────

    rows = conn.execute(
        "SELECT overall_level, COUNT(*) AS n FROM scans WHERE status='ok' GROUP BY overall_level"
    ).fetchall()
    risk_dist = {r["overall_level"]: r["n"] for r in rows}

    # ── Finding frequency (all platforms combined) ───────────────────────────

    finding_rows = conn.execute("""
        SELECT f.title, f.severity, COUNT(DISTINCT f.scan_id) AS affected
        FROM findings f
        JOIN scans s ON s.id = f.scan_id
        WHERE s.status = 'ok'
        GROUP BY f.title, f.severity
        ORDER BY affected DESC
    """).fetchall()

    top_findings = []
    for r in finding_rows:
        pct = round(r["affected"] / ok_scans * 100, 1) if ok_scans else 0
        top_findings.append({
            "title":               r["title"],
            "severity":            r["severity"],
            "affected_sites":      r["affected"],
            "affected_percentage": pct,
        })

    # ── Per-platform breakdown ───────────────────────────────────────────────

    platforms = [r[0] for r in conn.execute(
        "SELECT DISTINCT platform FROM sites"
    ).fetchall()]

    per_platform: dict = {}
    for plat in platforms:
        plat_ok = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status='ok' AND platform=?", (plat,)
        ).fetchone()[0]
        plat_total = conn.execute(
            "SELECT COUNT(*) FROM sites WHERE platform=?", (plat,)
        ).fetchone()[0]

        if plat_ok == 0:
            per_platform[plat] = {
                "total_sites": plat_total,
                "successful_scans": 0,
                "risk_distribution": {},
                "top_findings": [],
            }
            continue

        p_risk = conn.execute("""
            SELECT overall_level, COUNT(*) AS n
            FROM scans WHERE status='ok' AND platform=?
            GROUP BY overall_level
        """, (plat,)).fetchall()

        p_findings = conn.execute("""
            SELECT f.title, f.severity, COUNT(DISTINCT f.scan_id) AS affected
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE s.status='ok' AND s.platform=?
            GROUP BY f.title, f.severity
            ORDER BY affected DESC
            LIMIT 10
        """, (plat,)).fetchall()

        per_platform[plat] = {
            "total_sites":        plat_total,
            "successful_scans":   plat_ok,
            "risk_distribution":  {r["overall_level"]: r["n"] for r in p_risk},
            "top_findings": [
                {
                    "title":               r["title"],
                    "severity":            r["severity"],
                    "affected_sites":      r["affected"],
                    "affected_percentage": round(r["affected"] / plat_ok * 100, 1),
                }
                for r in p_findings
            ],
        }

    # ── Scanner-level stats ──────────────────────────────────────────────────

    scanner_avg = conn.execute("""
        SELECT
            ROUND(AVG(headers_score), 1) AS headers_avg,
            ROUND(AVG(dns_score),     1) AS dns_avg,
            ROUND(AVG(ssl_score),     1) AS ssl_avg,
            ROUND(AVG(overall_score), 1) AS overall_avg
        FROM scans WHERE status='ok'
    """).fetchone()

    # ── Headline stats (4-5 most striking) ──────────────────────────────────

    scored = sorted(
        top_findings,
        key=lambda f: f["affected_percentage"] * SEVERITY_WEIGHT.get(f["severity"], 1),
        reverse=True,
    )
    headline_stats = []
    for f in scored[:5]:
        weight   = SEVERITY_WEIGHT.get(f["severity"], 1)
        headline = _make_headline(f)
        headline_stats.append({
            "headline":            headline,
            "title":               f["title"],
            "severity":            f["severity"],
            "affected_percentage": f["affected_percentage"],
            "impact_score":        round(f["affected_percentage"] * weight, 1),
        })

    # ── Assemble output ──────────────────────────────────────────────────────

    out = {
        "generated_at":    _utcnow(),
        "profile":         "research-safe (headers + dns + ssl only)",
        "total_sites":     total_sites,
        "successful_scans": ok_scans,
        "failed_scans":    err_scans,
        "success_rate_pct": success_rate,
        "scanner_averages": {
            "headers_risk_score": scanner_avg["headers_avg"],
            "dns_risk_score":     scanner_avg["dns_avg"],
            "ssl_risk_score":     scanner_avg["ssl_avg"],
            "overall_risk_score": scanner_avg["overall_avg"],
        },
        "risk_distribution":  risk_dist,
        "top_findings":       top_findings,
        "per_platform":       per_platform,
        "headline_stats":     headline_stats,
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_JSON, "w") as fh:
        json.dump(out, fh, indent=2)

    conn.close()

    print(f"✅ aggregates.json written → {OUT_JSON}", flush=True)
    print(f"\n📊 Quick summary:", flush=True)
    print(f"   Sites:        {total_sites}  (success rate: {success_rate}%)", flush=True)
    print(f"   Risk dist:    {risk_dist}", flush=True)
    print(f"   Avg scores:   headers={scanner_avg['headers_avg']}  "
          f"dns={scanner_avg['dns_avg']}  ssl={scanner_avg['ssl_avg']}", flush=True)
    print(f"\n🔥 Headline stats:", flush=True)
    for h in headline_stats:
        print(f"   [{h['severity'].upper():8}] {h['affected_percentage']:5.1f}%  {h['title']}", flush=True)


def _make_headline(f: dict) -> str:
    pct  = f["affected_percentage"]
    sev  = f["severity"]
    title = f["title"].lower()
    return (
        f"{pct:.0f}% of scanned e-commerce stores have a {sev} finding: {title.rstrip('.')}."
    )


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    main()
