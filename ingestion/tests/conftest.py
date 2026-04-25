"""
conftest.py — pytest fixtures and configuration.
"""

import os
import pytest
import tempfile
import json
from typing import Dict, Any, Generator
from unittest.mock import Mock, patch

# مؤقت لاختبارات Redis
@pytest.fixture
def mock_redis():
    """Mock Redis client for queue tests."""
    with patch('ingestion.queue.get_client') as mock_get_client:
        mock_client = Mock()
        mock_client.rpush.return_value = 1
        mock_client.ping.return_value = True
        mock_client.llen.return_value = 0
        mock_get_client.return_value = mock_client
        yield mock_client

# عينة من أحداث Cowrie
@pytest.fixture
def cowrie_login_failed() -> Dict[str, Any]:
    """Sample Cowrie login failed event."""
    return {
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

@pytest.fixture
def cowrie_login_success() -> Dict[str, Any]:
    """Sample Cowrie login success event."""
    return {
        "eventid": "cowrie.login.success",
        "timestamp": "2026-04-24T11:00:00Z",
        "src_ip": "10.0.0.5",
        "username": "root",
        "password": "toor",
        "session": "abc123",
        "sensor": "cowrie-prod",
        "protocol": "ssh",
    }

@pytest.fixture
def cowrie_command() -> Dict[str, Any]:
    """Sample Cowrie command event."""
    return {
        "eventid": "cowrie.command.input",
        "timestamp": "2026-04-24T12:00:00Z",
        "src_ip": "1.2.3.4",
        "session": "sess-999",
        "sensor": "cowrie",
        "command": "cat /etc/passwd",
        "protocol": "ssh",
    }

# عينة من أحداث Honeytrap
@pytest.fixture
def honeytrap_connection() -> Dict[str, Any]:
    """Sample Honeytrap connection event."""
    return {
        "type": "connection",
        "timestamp": "2026-04-24T09:00:00Z",
        "source-ip": "203.0.113.5",
        "source-port": 12345,
        "destination-ip": "10.0.0.1",
        "destination-port": 22,
        "protocol": "tcp",
        "sensor-id": "ht-sensor-01",
    }

# ملف JSON مؤقت للاختبارات
@pytest.fixture
def temp_jsonl_file() -> Generator[str, None, None]:
    """Create a temporary JSONL file for file tail tests."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.jsonl', delete=False) as f:
        temp_path = f.name
        # كتابة بعض الأحداث الأولية
        events = [
            {"eventid": "test.1", "src_ip": "1.1.1.1"},
            {"eventid": "test.2", "src_ip": "2.2.2.2"},
        ]
        for event in events:
            f.write(json.dumps(event) + '\n')
    
    yield temp_path
    
    # تنظيف
    os.unlink(temp_path)

# متغيرات بيئة للاختبارات
@pytest.fixture(autouse=True)
def test_env_vars():
    """Set test environment variables."""
    with patch.dict(os.environ, {
        'REDIS_HOST': 'localhost',
        'REDIS_PORT': '6379',
        'REDIS_DB': '0',
        'REDIS_PASSWORD': '',
        'HMAC_SECRET': 'test_secret_key',
        'FORCE_DISABLE_HMAC': 'true',
        'LOG_LEVEL': 'DEBUG',
        'ALLOWED_IPS': '127.0.0.1,192.168.1.0/24',
    }):
        yield
