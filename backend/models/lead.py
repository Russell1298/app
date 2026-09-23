"""
Request and response models for lead capture.

Email is validated with a regex rather than pydantic's EmailStr so the backend
does not gain an email-validator dependency for one field. The authoritative
test of an address is whether a reply reaches it.
"""

import re
from pydantic import BaseModel, Field, field_validator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(\.[^@\s.]+)+$")

_SOURCES = {"scan_report", "pdf_request", "contact_page"}


class LeadRequest(BaseModel):
    email: str = Field(max_length=320)
    domain: str | None = Field(default=None, max_length=253)
    scan_id: str | None = None
    security_score: int | None = Field(default=None, ge=0, le=100)
    urgent_findings: int | None = Field(default=None, ge=0, le=1000)
    message: str | None = Field(default=None, max_length=2000)
    source: str = "scan_report"

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Enter a valid email address")
        return v

    @field_validator("source")
    @classmethod
    def _check_source(cls, v: str) -> str:
        return v if v in _SOURCES else "scan_report"


class LeadResponse(BaseModel):
    ok: bool = True


class LeadItem(BaseModel):
    """Owner-facing view of a captured lead."""

    id: str
    email: str
    domain: str | None
    scan_id: str | None
    security_score: int | None
    urgent_findings: int | None
    message: str | None
    source: str
    contacted: bool
    created_at: str
