"""
normalize.py — Converts raw Honeytrap events into the unified Cerebrum format.

Supports both:
- Honeytrap native format (uses 'type')
- Cowrie format (uses 'eventid')
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. INPUT SCHEMA
# ---------------------------------------------------------------------------

class HoneytrapEvent(BaseModel):
    """
    Represents a raw event as emitted by Honeytrap or Cowrie.
    Supports both 'type' (Honeytrap) and 'eventid' (Cowrie).
    """

    type: Optional[str] = Field(None, description="Event type (Honeytrap format)")
    eventid: Optional[str] = Field(None, description="Event ID (Cowrie format)")

    username: Optional[str] = Field(None)
    password: Optional[str] = Field(None)
    session: Optional[str] = Field(None)
    sensor: Optional[str] = Field(None)
    command: Optional[str] = Field(None)
    message: Optional[str] = Field(None)

    timestamp: Optional[str] = Field(None)
    source_ip: Optional[str] = Field(None, alias="source-ip")
    source_port: Optional[int] = Field(None, alias="source-port")
    destination_ip: Optional[str] = Field(None, alias="destination-ip")
    destination_port: Optional[int] = Field(None, alias="destination-port")
    protocol: Optional[str] = Field(None)

    src_ip: Optional[str] = Field(None)
    src_port: Optional[int] = Field(None)
    dst_ip: Optional[str] = Field(None)
    dst_port: Optional[int] = Field(None)

    payload: Optional[str] = Field(None)
    sensor_id: Optional[str] = Field(None, alias="sensor-id")
    session_id: Optional[str] = Field(None, alias="session-id")

    model_config = {"populate_by_name": True, "extra": "allow"}

    @field_validator("message", mode="before")
    @classmethod
    def coerce_message(cls, v: Any) -> Optional[str]:
        """Cowrie sometimes sends message as a list — convert to string."""
        if isinstance(v, list):
            return " ".join(str(i) for i in v) if v else None
        return v

    @field_validator("type", "eventid", mode="before")
    @classmethod
    def normalize_type(cls, v: Optional[str]) -> Optional[str]:
        if v:
            return v.strip().lower()
        return v

    @model_validator(mode="after")
    def validate_event_type(self) -> "HoneytrapEvent":
        """Ensure we have either 'type' or 'eventid'"""
        if not self.type and not self.eventid:
            raise ValueError("Either 'type' or 'eventid' must be provided")
        return self

    def get_event_type(self) -> str:
        return self.eventid or self.type or "unknown"

    def get_src_ip(self) -> Optional[str]:
        return self.src_ip or self.source_ip

    def get_src_port(self) -> Optional[int]:
        return self.src_port or self.source_port

    def get_dst_ip(self) -> Optional[str]:
        return self.dst_ip or self.destination_ip

    def get_dst_port(self) -> Optional[int]:
        return self.dst_port or self.destination_port

    def get_session_id(self) -> Optional[str]:
        return self.session or self.session_id


# ---------------------------------------------------------------------------
# 2. OUTPUT SCHEMA
# ---------------------------------------------------------------------------

class CerebrumEvent(BaseModel):
    """
    Normalized, enriched event consumed by Cerebrum and downstream services.
    Every field is guaranteed to exist (None where unavailable).
    """

    event_id: str
    event_type: str
    timestamp: str

    src_ip: Optional[str]
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    protocol: Optional[str]

    sensor_id: Optional[str]
    session_id: Optional[str]
    payload: Optional[str]

    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None

    raw_extra: dict
    ingested_at: str
    schema_version: str = "1.0"


# ---------------------------------------------------------------------------
# 3. HELPERS
# ---------------------------------------------------------------------------

def _parse_timestamp(raw: Optional[str]) -> str:
    """Coerce whatever we get into UTC ISO-8601."""
    if not raw:
        return datetime.now(timezone.utc).isoformat()

    if raw.endswith('Z'):
        raw = raw[:-1] + '+00:00'

    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            continue

    try:
        epoch = float(raw)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (ValueError, OSError):
        pass

    log.warning("Could not parse timestamp %r — using now()", raw)
    return datetime.now(timezone.utc).isoformat()


def _make_event_id(event: HoneytrapEvent, ts: str) -> str:
    """Deterministic 32-char fingerprint for deduplication."""
    fingerprint = (
        f"{event.get_event_type()}|{event.get_src_ip()}|"
        f"{event.get_src_port()}|{ts}|{event.payload or event.command or ''}"
    )
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# 4. MAIN NORMALIZATION FUNCTION
# ---------------------------------------------------------------------------

def normalize(honeytrap_event: dict[str, Any]) -> Optional[dict]:
    """
    Validate a raw event dict and return a Cerebrum-format dict.
    Returns None on validation failure so callers skip bad records safely.
    """
    try:
        raw = HoneytrapEvent.model_validate(honeytrap_event)

        event_type = raw.get_event_type()
        ts = _parse_timestamp(raw.timestamp)
        event_id = _make_event_id(raw, ts)
        ingested_at = datetime.now(timezone.utc).isoformat()

        src_ip = raw.get_src_ip()
        src_port = raw.get_src_port()
        dst_ip = raw.get_dst_ip()
        dst_port = raw.get_dst_port()
        session_id = raw.get_session_id()
        sensor_id = raw.sensor or raw.sensor_id

        extras: dict = {}
        if raw.model_extra:
            extras.update(raw.model_extra)

        cerebrum = CerebrumEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=ts,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=raw.protocol,
            sensor_id=sensor_id,
            session_id=session_id,
            payload=raw.payload or raw.message,
            username=raw.username,
            password=raw.password,
            command=raw.command,
            raw_extra=extras,
            ingested_at=ingested_at,
        )

        log.debug("Normalized event %s (type=%s)", event_id, event_type)
        return cerebrum.model_dump()

    except ValidationError as exc:
        log.error(
            "Validation failed | input=%s | errors=%s",
            honeytrap_event,
            exc.errors(),
        )
        return None

    except Exception as exc:  # noqa: BLE001
        log.exception("Unexpected normalization error for event=%s: %s", honeytrap_event, exc)
        return None
