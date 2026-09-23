#!/usr/bin/env bash
# SiteGuard Research Pipeline
# Runs all three phases in sequence and prints a final summary.
# Usage: bash scripts/research/run_all.sh
#        bash scripts/research/run_all.sh --skip-targets  (resume from existing targets.csv)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DATA_DIR="$REPO_ROOT/data"
LOG_DIR="$DATA_DIR/logs"

mkdir -p "$LOG_DIR"
START_TS=$(date +%s)

echo "══════════════════════════════════════════════════════"
echo "  SiteGuard Research Pipeline"
echo "  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "══════════════════════════════════════════════════════"

# ── Phase 1 ──────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--skip-targets" ]]; then
    echo ""
    echo "⏭  Phase 1 skipped (--skip-targets)"
    if [[ ! -f "$DATA_DIR/targets.csv" ]]; then
        echo "ERROR: --skip-targets used but $DATA_DIR/targets.csv does not exist" >&2
        exit 1
    fi
    echo "   Using existing $(wc -l < "$DATA_DIR/targets.csv") rows in targets.csv"
else
    echo ""
    echo "━━ Phase 1: Build Target List ━━━━━━━━━━━━━━━━━━━━━━"
    python3 "$SCRIPT_DIR/01_build_targets.py" 2>&1 | tee "$LOG_DIR/phase1.log"
    echo "   Log → $LOG_DIR/phase1.log"
fi

# ── Phase 2 ──────────────────────────────────────────────────────────────────
echo ""
echo "━━ Phase 2: Run Research-Safe Scans ━━━━━━━━━━━━━━━━━"
python3 "$SCRIPT_DIR/02_run_scans.py" 2>&1 | tee "$LOG_DIR/phase2.log"
echo "   Log → $LOG_DIR/phase2.log"

# ── Phase 3 ──────────────────────────────────────────────────────────────────
echo ""
echo "━━ Phase 3: Aggregate Results ━━━━━━━━━━━━━━━━━━━━━━━"
python3 "$SCRIPT_DIR/03_aggregate.py" 2>&1 | tee "$LOG_DIR/phase3.log"
echo "   Log → $LOG_DIR/phase3.log"

# ── Summary ──────────────────────────────────────────────────────────────────
END_TS=$(date +%s)
ELAPSED=$(( END_TS - START_TS ))
echo ""
echo "══════════════════════════════════════════════════════"
echo "  Pipeline complete in ${ELAPSED}s"
echo "  Outputs:"
echo "    $DATA_DIR/targets.csv"
echo "    $DATA_DIR/research.db"
echo "    $DATA_DIR/aggregates.json"
echo "══════════════════════════════════════════════════════"
