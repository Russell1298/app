PENALTY = {"high": 30, "medium": 10, "low": 3, "info": 0}

SCANNER_MAX = {
    "headers":  100,
    "dns":       90,
    "ssl":      100,
    "exposure": 120,
    "secrets":  100,
}

SCANNER_WEIGHTS = {
    "ssl":      0.28,
    "headers":  0.23,
    "dns":      0.22,
    "exposure": 0.17,
    "secrets":  0.10,
}

# Trigger ID -> minimum overall risk score (floor cap applied after weighted average)
CRITICAL_CAPS: dict[str, int] = {
    "env_exposed":            85,
    "git_exposed":            80,
    "db_admin_exposed":       75,
    "backup_exposed":         75,
    "config_exposed":         80,
    "debug_panel_exposed":    70,
    "live_secret":            90,
    "private_key":            90,
    "cert_expired":           70,
    "cert_self_signed":       60,
    "cert_hostname_mismatch": 65,
}


def risk_level(score: int) -> str:
    if score <= 14:
        return "low"
    if score <= 34:
        return "medium"
    if score <= 64:
        return "high"
    return "critical"


def scanner_score(total_penalty: int | float, scanner_name: str) -> int:
    max_penalty = SCANNER_MAX[scanner_name]
    return min(100, round((total_penalty / max_penalty) * 100))
