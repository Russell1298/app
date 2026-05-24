from pydantic import BaseModel, field_validator
from typing import Literal
from datetime import datetime, timezone
import re


class ScanRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v: str) -> str:
        v = v.strip().lower()
        # Strip scheme if user pastes a full URL
        v = re.sub(r"^https?://", "", v)
        # Strip trailing slashes and paths
        v = v.split("/")[0]
        if not re.match(r"^[a-z0-9][a-z0-9\-\.]{0,252}[a-z0-9]$", v):
            raise ValueError("Invalid domain name")
        return v


class HeaderFinding(BaseModel):
    header: str
    status: Literal["present", "missing", "weak"]
    severity: Literal["low", "medium", "high"]
    value: str | None
    description: str
    remediation: str


class InformationLeakFinding(BaseModel):
    header: str
    value: str
    severity: Literal["low", "medium", "high"]
    description: str
    remediation: str


class HeaderScanResult(BaseModel):
    domain: str
    scanned_url: str
    scan_timestamp: str
    findings: list[HeaderFinding]
    information_leaks: list[InformationLeakFinding]
    risk_score: int          # 0-100
    risk_level: Literal["low", "medium", "high", "critical"]
    summary: dict


class DNSRecord(BaseModel):
    record_type: str
    values: list[str]


class DNSFinding(BaseModel):
    check: str
    status: Literal["pass", "fail", "warn", "info"]
    severity: Literal["low", "medium", "high"] | None
    description: str
    remediation: str | None


class DNSScanResult(BaseModel):
    domain: str
    scan_timestamp: str
    records: list[DNSRecord]
    findings: list[DNSFinding]
    risk_score: int
    risk_level: Literal["low", "medium", "high", "critical"]
    summary: dict


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
