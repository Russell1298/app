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


class ExposureFinding(BaseModel):
    path: str
    label: str
    status_code: int
    exposed: bool
    severity: Literal["low", "medium", "high", "info"]
    description: str
    remediation: str | None
    confidence: Literal["confirmed", "likely", "possible"] | None = None


class ExposureScanResult(BaseModel):
    domain: str
    scan_timestamp: str
    findings: list[ExposureFinding]
    risk_score: int
    risk_level: Literal["low", "medium", "high", "critical"]
    summary: dict


class FingerprintMatch(BaseModel):
    name: str
    category: Literal["cms", "framework", "cdn", "server", "library"]
    confidence: Literal["low", "medium", "high"]
    evidence: str


class FingerprintScanResult(BaseModel):
    domain: str
    scan_timestamp: str
    matches: list[FingerprintMatch]
    summary: dict


class CertInfo(BaseModel):
    subject: str
    issuer: str
    not_before: str
    not_after: str
    days_until_expiry: int
    is_self_signed: bool
    sans: list[str]
    serial_number: str


class TLSVersionCheck(BaseModel):
    version: str
    supported: bool | None  # None = could not determine (OS-level restriction)


class SSLFinding(BaseModel):
    check: str
    status: Literal["pass", "fail", "warn", "info"]
    severity: Literal["low", "medium", "high"] | None
    description: str
    remediation: str | None


class SSLScanResult(BaseModel):
    domain: str
    port: int
    scan_timestamp: str
    certificate: CertInfo | None
    tls_versions: list[TLSVersionCheck]
    findings: list[SSLFinding]
    risk_score: int
    risk_level: Literal["low", "medium", "high", "critical"]
    summary: dict


class SubdomainEntry(BaseModel):
    subdomain: str
    resolves: bool
    ip_addresses: list[str]


class SubdomainScanResult(BaseModel):
    domain: str
    scan_timestamp: str
    subdomains: list[SubdomainEntry]
    summary: dict


class SecretFinding(BaseModel):
    pattern_name: str
    severity: Literal["low", "medium", "high"]
    location: str        # "html", "inline-script", "javascript"
    source_url: str
    match_preview: str   # partially redacted — never logs real secrets


class SecretScanResult(BaseModel):
    domain: str
    scan_timestamp: str
    findings: list[SecretFinding]
    files_scanned: int
    risk_score: int
    risk_level: Literal["low", "medium", "high", "critical"]
    summary: dict


class FullScanResult(BaseModel):
    scan_id: str | None = None
    domain: str
    scan_timestamp: str
    headers: HeaderScanResult
    dns: DNSScanResult
    ssl: SSLScanResult
    exposure: ExposureScanResult
    fingerprint: FingerprintScanResult
    subdomains: SubdomainScanResult | None = None  # None on old records
    secrets: SecretScanResult | None = None
    overall_risk_score: int
    overall_risk_level: Literal["low", "medium", "high", "critical"]
    top_findings: list[dict]


class ScanHistoryItem(BaseModel):
    scan_id: str
    domain: str
    scan_timestamp: str
    overall_risk_score: int
    overall_risk_level: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
