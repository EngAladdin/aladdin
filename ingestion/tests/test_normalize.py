import pytest
from ingestion.normalize import normalize_event

def test_normalize_cowrie_event():
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
        "sensor": "cowrie"
    }
    result = normalize_event(event)
    assert result is not None
    assert "event_id" in result
