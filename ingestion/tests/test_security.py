"""
test_security.py — Unit tests for ingestion/security.py.

Run with:
    pytest ingestion/tests/test_security.py -v
"""

import pytest
import os
from unittest.mock import patch
from ingestion import security


class TestSecurity:
    """Test HMAC and IP validation."""
    
    def test_sign_payload_success(self):
        """Should sign payload correctly."""
        with patch.dict(os.environ, {'HMAC_SECRET': 'test_secret'}):
            # Re-import to pick up new env var
            import importlib
            importlib.reload(security)
            
            payload = b"test message"
            signature = security.sign_payload(payload)
            
            assert isinstance(signature, str)
            assert len(signature) == 64  # SHA256 hex digest
            assert security.verify_signature(payload, signature)
    
    def test_sign_payload_no_secret(self):
        """Should raise error when HMAC_SECRET not set."""
        with patch.dict(os.environ, {}, clear=True):
            import importlib
            importlib.reload(security)
            
            with pytest.raises(RuntimeError, match="HMAC_SECRET is not set"):
                security.sign_payload(b"test")
    
    def test_verify_signature_valid(self):
        """Should return True for valid signature."""
        with patch.dict(os.environ, {'HMAC_SECRET': 'test_secret', 'FORCE_DISABLE_HMAC': 'false'}):
            import importlib
            importlib.reload(security)
            
            payload = b"test message"
            signature = security.sign_payload(payload)
            
            assert security.verify_signature(payload, signature)
    
    def test_verify_signature_invalid(self):
        """Should return False for invalid signature."""
        with patch.dict(os.environ, {'HMAC_SECRET': 'test_secret', 'FORCE_DISABLE_HMAC': 'false'}):
            import importlib
            importlib.reload(security)
            
            payload = b"test message"
            result = security.verify_signature(payload, "invalid_signature")
            
            assert result is False
    
    def test_verify_signature_with_sha256_prefix(self):
        """Should handle 'sha256=' prefix in signature."""
        with patch.dict(os.environ, {'HMAC_SECRET': 'test_secret', 'FORCE_DISABLE_HMAC': 'false'}):
            import importlib
            importlib.reload(security)
            
            payload = b"test"
            sig = security.sign_payload(payload)
            
            # Test with sha256= prefix
            assert security.verify_signature(payload, f"sha256={sig}")
    
    def test_verify_signature_missing_signature(self):
        """Should return False when signature missing."""
        with patch.dict(os.environ, {'HMAC_SECRET': 'test_secret', 'FORCE_DISABLE_HMAC': 'false'}):
            import importlib
            importlib.reload(security)
            
            result = security.verify_signature(b"test", "")
            assert result is False
    
    def test_verify_signature_force_disabled(self):
        """Should bypass verification when FORCE_DISABLE_HMAC=true."""
        with patch.dict(os.environ, {'FORCE_DISABLE_HMAC': 'true'}):
            import importlib
            importlib.reload(security)
            
            # Even with wrong signature, should return True
            result = security.verify_signature(b"test", "wrong")
            assert result is True
    
    def test_is_ip_allowed_empty_whitelist(self):
        """Should allow all IPs when ALLOWED_IPS empty."""
        with patch.dict(os.environ, {'ALLOWED_IPS': ''}):
            import importlib
            importlib.reload(security)
            
            assert security.is_ip_allowed("1.2.3.4") is True
            assert security.is_ip_allowed("10.0.0.1") is True
            assert security.is_ip_allowed("192.168.1.1") is True
    
    def test_is_ip_allowed_single_ip(self):
        """Should allow specific IP."""
        with patch.dict(os.environ, {'ALLOWED_IPS': '192.168.1.100'}):
            import importlib
            importlib.reload(security)
            
            assert security.is_ip_allowed("192.168.1.100") is True
            assert security.is_ip_allowed("192.168.1.101") is False
    
    def test_is_ip_allowed_cidr(self):
        """Should allow CIDR range."""
        with patch.dict(os.environ, {'ALLOWED_IPS': '192.168.1.0/24'}):
            import importlib
            importlib.reload(security)
            
            assert security.is_ip_allowed("192.168.1.1") is True
            assert security.is_ip_allowed("192.168.1.254") is True
            assert security.is_ip_allowed("192.168.2.1") is False
    
    def test_is_ip_allowed_multiple_networks(self):
        """Should allow from multiple networks."""
        with patch.dict(os.environ, {'ALLOWED_IPS': '10.0.0.0/8,192.168.1.0/24'}):
            import importlib
            importlib.reload(security)
            
            assert security.is_ip_allowed("10.1.1.1") is True
            assert security.is_ip_allowed("192.168.1.100") is True
            assert security.is_ip_allowed("172.16.1.1") is False
    
    def test_is_ip_allowed_invalid_ip(self):
        """Should return False for invalid IP format."""
        with patch.dict(os.environ, {'ALLOWED_IPS
