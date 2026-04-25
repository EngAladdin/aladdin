"""
test_queue.py — Unit tests for ingestion/queue.py.

Run with:
    pytest ingestion/tests/test_queue.py -v
"""

import pytest
import json
import redis
from unittest.mock import Mock, patch, call
from ingestion import queue


class TestQueue:
    """Test Redis queue operations."""
    
    def test_push_event_success(self, mock_redis):
        """Should successfully push event to Redis."""
        event = {
            "event_id": "test123",
            "event_type": "test",
            "timestamp": "2026-04-24T10:00:00Z",
            "ingested_at": "2026-04-24T10:00:00Z",
            "schema_version": "1.0",
        }
        
        result = queue.push_event(event)
        
        assert result is True
        mock_redis.rpush.assert_called_once()
        args = mock_redis.rpush.call_args[0]
        assert args[0] == queue.QUEUE_KEY
        # Verify JSON serialization
        payload = json.loads(args[1])
        assert payload["event_id"] == "test123"
    
    def test_push_event_serialization_error(self, mock_redis):
        """Should handle JSON serialization errors."""
        event = {"event_id": "test", "invalid": set([1, 2, 3])}  # set is not JSON serializable
        
        result = queue.push_event(event)
        
        assert result is False
        mock_redis.rpush.assert_not_called()
    
    def test_push_event_retry_on_failure(self):
        """Should retry on Redis errors."""
        with patch('ingestion.queue.get_client') as mock_get_client:
            mock_client = Mock()
            # Fail twice, then succeed
            mock_client.rpush.side_effect = [
                redis.RedisError("Connection failed"),
                redis.RedisError("Timeout"),
                1  # Success
            ]
            mock_get_client.return_value = mock_client
            
            event = {"event_id": "test", "event_type": "test"}
            
            with patch('time.sleep') as mock_sleep:
                result = queue.push_event(event)
            
            assert result is True
            assert mock_client.rpush.call_count == 3
            mock_sleep.assert_called()
    
    def test_push_event_max_retries_exceeded(self):
        """Should drop event after max retries."""
        with patch('ingestion.queue.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.rpush.side_effect = redis.RedisError("Persistent failure")
            mock_get_client.return_value = mock_client
            
            event = {"event_id": "test", "event_type": "test"}
            
            with patch('time.sleep') as mock_sleep:
                result = queue.push_event(event)
            
            assert result is False
            assert mock_client.rpush.call_count == queue.MAX_RETRIES
            assert mock_sleep.call_count == queue.MAX_RETRIES - 1
    
    def test_queue_depth(self, mock_redis):
        """Should return current queue depth."""
        mock_redis.llen.return_value = 42
        
        depth = queue.queue_depth()
        
        assert depth == 42
        mock_redis.llen.assert_called_once_with(queue.QUEUE_KEY)
    
    def test_queue_depth_redis_error(self):
        """Should return -1 on Redis error."""
        with patch('ingestion.queue.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.llen.side_effect = redis.RedisError("Connection failed")
            mock_get_client.return_value = mock_client
            
            depth = queue.queue_depth()
            
            assert depth == -1
    
    def test_ping_success(self, mock_redis):
        """Should return True when Redis responds."""
        mock_redis.ping.return_value = True
        
        result = queue.ping()
        
        assert result is True
        mock_redis.ping.assert_called_once()
    
    def test_ping_failure(self):
        """Should return False when Redis is unreachable."""
        with patch('ingestion.queue.get_client') as mock_get_client:
            mock_client = Mock()
            mock_client.ping.side_effect = redis.RedisError("Connection failed")
            mock_get_client.return_value = mock_client
            
            result = queue.ping()
            
            assert result is False
    
    def test_redis_connection_pool_singleton(self):
        """Should create single connection pool instance."""
        with patch('redis.ConnectionPool') as MockPool:
            queue._pool = None
            
            pool1 = queue._get_pool()
            pool2 = queue._get_pool()
            
            assert pool1 is pool2
            MockPool.assert_called_once()
    
    def test_push_event_handles_complex_objects(self, mock_redis):
        """Should handle events with datetime objects."""
        from datetime import datetime
        
        event = {
            "event_id": "test",
            "timestamp": datetime(2026, 4, 24, 10, 0, 0),
            "nested": {"key": "value"},
            "list": [1, 2, 3]
        }
        
        result = queue.push_event(event)
        
        assert result is True
        # Verify datetime was converted to string
        args = mock_redis.rpush.call_args[0]
        payload = json.loads(args[1])
        assert isinstance(payload["timestamp"], str)
        assert payload["nested"]["key"] == "value"
        assert payload["list"] == [1, 2, 3]
