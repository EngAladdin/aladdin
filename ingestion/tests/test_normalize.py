"""
test_normalize.py — Unit tests for ingestion/normalize.py

Run with:
    pytest ingestion/tests/test_normalize.py -v
"""

import pytest
from ingestion.normalize import normalize


# ---------------------------------------------------------------------------
# Happy path — Cowrie events
# ---------------------------------------------------------------------------

def test_normalize_cowrie_login_failed():
    """Standard cowrie.login.failed event."""
    event = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-04-24T10:00:00Z",
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dst_ip": "172.18.0.3",
        "dst_port": 2222,
        "username": "attacker",
        "password": "admin123",
        "session": "test-001",
        "sensor": "cowrie",
        "protocol": "ssh",
    }
    result = normalize(event)
    assert result is not None
    assert "event_id" in result
    assert result["event_type"] == "cowrie.login.failed"
    assert result["src_ip"] == "192.168.1.100"
    assert result["src_port"] == 54321
    assert result["username"] == "attacker"
    assert result["password"] == "admin123"
    assert result["session_id"] == "test-001"
    assert result["sensor_id"] == "cowrie"
    assert result["schema_version"] == "1.0"


def test_normalize_cowrie_login_success():
    """cowrie.login.success with standard fields."""
    event = {
        "eventid": "cowrie.login.success",
        "timestamp": "2026-04-24T11:00:00Z",
        "src_ip": "10.0.0.5",
        "username": "root",
        "password": "toor",
        "session": "abc123",
        "sensor": "cowrie-prod",
        "protocol": "ssh",
    }
    result = normalize(event)
    assert result is not None
    assert result["event_type"] == "cowrie.login.success"
    assert result["username"] == "root"


def test_normalize_cowrie_command_input():
    """cowrie.command.input — attacker ran a command."""
    event = {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-04-24T12:00:00Z",
        "src_ip": "1.2.3.4",
        "session": "sess-999",
        "sensor": "cowrie",
        "command": "cat /etc/passwd",
        "protocol": "ssh",
    }
    result = normalize(event)
    assert result is not None
    assert result["event_type"] == "cowrie.command.input"
    assert result["command"] == "cat /etc/passwd"


def test_normalize_cowrie_session_params_message_list():
    """
    cowrie.session.params sends message as an empty list [].
    Should NOT fail — should coerce to None.
    """
    event = {
        "eventid": "cowrie.session.params",
        "timestamp": "2026-04-24T22:41:41.642106Z",
        "src_ip": "172.19.0.1",
        "session": "d92f973d03c4",
        "sensor": "41a7e3d42b7a",
        "protocol": "ssh",
        "message": [],          # ← Cowrie bug: sends list instead of string
        "arch": "linux-x64-lsb",
    }
    result = normalize(event)
    assert result is not None, "Should not fail on empty list message"
    assert result["payload"] is None


def test_normalize_cowrie_session_params_message_list_with_items():
    """message as a list with items — should join to string."""
    event = {
        "eventid": "cowrie.session.params",
        "timestamp": "2026-04-24T12:00:00Z",
        "src_ip": "5.6.7.8",
        "session": "s1",
        "sensor": "cowrie",
        "protocol": "ssh",
        "message": ["hello", "world"],
    }
    result = normalize(event)
    assert result is not None
    assert result["payload"] == "hello world"


# ---------------------------------------------------------------------------
# Happy path — Honeytrap events (legacy format)
# ---------------------------------------------------------------------------

def test_normalize_honeytrap_connection():
    """Standard Honeytrap connection event using kebab-case fields."""
    event = {
        "type": "connection",
        "timestamp": "2026-04-24T09:00:00Z",
        "source-ip": "203.0.113.5",
        "source-port": 12345,
        "destination-ip": "10.0.0.1",
        "destination-port": 22,
        "protocol": "tcp",
        "sensor-id": "ht-sensor-01",
    }
    result = normalize(event)
    assert result is not None
    assert result["event_type"] == "connection"
    assert result["src_ip"] == "203.0.113.5"
    assert result["dst_port"] == 22
    assert result["sensor_id"] == "ht-sensor-01"


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def test_normalize_timestamp_z_suffix():
    """Timestamps ending in Z should parse correctly."""
    event = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-01-15T08:30:00Z",
        "src_ip": "1.1.1.1",
        "sensor": "cowrie",
    }
    result = normalize(event)
    assert result is not None
    assert "2026-01-15" in result["timestamp"]


def test_normalize_missing_timestamp():
    """Missing timestamp should fall back to now()."""
    event = {
        "eventid": "cowrie.login.failed",
        "src_ip": "1.1.1.1",
        "sensor": "cowrie",
    }
    result = normalize(event)
    assert result is not None
    assert result["timestamp"] is not None


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_normalize_same_event_same_id():
    """Same event should always produce the same event_id."""
    event = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-04-24T10:00:00Z",
        "src_ip": "9.9.9.9",
        "sensor": "cowrie",
    }
    r1 = normalize(event)
    r2 = normalize(event)
    assert r1["event_id"] == r2["event_id"]


def test_normalize_different_events_different_ids():
    """Different source IPs should produce different event_ids."""
    base = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-04-24T10:00:00Z",
        "sensor": "cowrie",
    }
    r1 = normalize({**base, "src_ip": "1.1.1.1"})
    r2 = normalize({**base, "src_ip": "2.2.2.2"})
    assert r1["event_id"] != r2["event_id"]


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------

def test_normalize_missing_type_and_eventid():
    """Should return None when neither type nor eventid is present."""
    result = normalize({"src_ip": "1.2.3.4", "timestamp": "2026-04-24T10:00:00Z"})
    assert result is None


def test_normalize_empty_dict():
    """Empty dict should return None."""
    result = normalize({})
    assert result is None


def test_normalize_non_dict():
    """Non-dict input should return None without crashing."""
    result = normalize("this is not a dict")  # type: ignore
    assert result is None


def test_normalize_garbage_data():
    """Completely invalid data should return None without crashing."""
    result = normalize({"random_key": 12345, "another": [1, 2, 3]})
    assert result is None


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

def test_normalize_output_has_required_fields():
    """Output dict must always contain all required CerebrumEvent fields."""
    event = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-04-24T10:00:00Z",
        "src_ip": "5.5.5.5",
        "sensor": "cowrie",
    }
    result = normalize(event)
    assert result is not None

    required_fields = [
        "event_id", "event_type", "timestamp", "src_ip", "src_port",
        "dst_ip", "dst_port", "protocol", "sensor_id", "session_id",
        "payload", "username", "password", "command",
        "raw_extra", "ingested_at", "schema_version",
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


def test_normalize_raw_extra_captures_unknown_fields():
    """Unknown fields from Cowrie should land in raw_extra."""
    event = {
        "eventid": "cowrie.login.failed",
        "timestamp": "2026-04-24T10:00:00Z",
        "src_ip": "6.6.6.6",
        "sensor": "cowrie",
        "arch": "linux-x64-lsb",         # unknown field
        "uuid": "bafc61de-32ec-11f1",    # unknown field
    }
    result = normalize(event)
    assert result is not None
    assert "arch" in result["raw_extra"] or result["raw_extra"] is not None
