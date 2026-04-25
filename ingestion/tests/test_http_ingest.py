"""
test_http_ingest.py — Unit tests for ingestion/http_ingest.py.

Run with:
    pytest ingestion/tests/test_http_ingest.py -v
"""

import pytest
import json
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
from ingestion.http_ingest import app

client = TestClient(app)


class TestHTTPIngest:
    """Test HTTP ingestion endpoints."""
    
    @patch('ingestion.http_ingest.push_event')
    @patch('ingestion.http_ingest.validate_request')
    def test_ingest_event_success(self, mock_validate, mock_push):
        """Should accept valid event."""
        mock_validate.return_value = (True, "")
        mock_push.return_value = True
        
        event = {"eventid": "test", "src_ip": "1.1.1.1", "sensor": "test"}
        
        response = client.post(
            "/ingest/event",
            json=event,
            headers={"X-Honeytrap-Signature": "test_sig"}
        )
        
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "accepted"
        assert data["queued"] == 1
        assert data["failed"] == 0
    
    @patch('ingestion.http_ingest.validate_request')
    def test_ingest_event_forbidden_ip(self, mock_validate):
        """Should reject requests from disallowed IP."""
        mock_validate.return_value = (False, "IP not allowed")
        
        response = client.post(
            "/ingest/event",
            json={"test": "data"},
            headers={"X-Honeytrap-Signature": "sig"}
        )
        
        assert response.status_code == 403
        assert "not allowed" in response.text
    
    def test_ingest_event_invalid_json(self):
        """Should reject invalid JSON."""
        response = client.post(
            "/ingest/event",
            data="not valid json",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 400
        assert "JSON" in response.text
    
    @patch('ingestion.http_ingest.normalize')
    @patch('ingestion.http_ingest.validate_request')
    def test_ingest_batch_events(self, mock_validate, mock_normalize):
        """Should handle batch events."""
        mock_validate.return_value = (True, "")
        mock_normalize.return_value = {
            "event_id": "test",
            "event_type": "test",
            "timestamp": "2026-01-01T00:00:00Z",
            "ingested_at": "2026-01-01T00:00:00Z",
            "schema_version": "1.0"
        }
        
        events = [
            {"eventid": "test1", "src_ip": "1.1.1.1"},
            {"eventid": "test2", "src_ip": "2.2.2.2"},
            {"eventid": "test3", "src_ip": "3.3.3.3"}
        ]
        
        response = client.post(
            "/ingest/event",
            json=events,
            headers={"X-Honeytrap-Signature": "sig"}
        )
        
        assert response.status_code == 202
        data = response.json()
        assert data["total"] == 3
        assert data["queued"] == 3
    
    @patch('ingestion.http_ingest.ping')
    def test_health_ok(self, mock_ping):
        """Health endpoint should return 200 when Redis is up."""
        mock_ping.return_value = True
        
        response = client.get("/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["redis"] == "up"
    
    @patch('ingestion.http_ingest.ping')
    def test_health_degraded(self, mock_ping):
        """Health endpoint should return 503 when Redis is down."""
        mock_ping.return_value = False
        
        response = client.get("/health")
        
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "degraded"
        assert data["redis"] == "down"
    
    @patch('ingestion.http_ingest.queue_depth')
    def test_metrics(self, mock_depth):
        """Metrics endpoint should return queue depth."""
        mock_depth.return_value = 42
        
        response = client.get("/metrics")
        
        assert response.status_code == 200
        data = response.json()
        assert data["queue_depth"] == 42
    
    def test_method_not_allowed(self):
        """GET on /ingest/event should return 405."""
        response = client.get("/ingest/event")
        assert response.status_code == 405
    
    def test_not_found(self):
        """Invalid path should return 404."""
        response = client.get("/nonexistent")
        assert response.status_code == 404
