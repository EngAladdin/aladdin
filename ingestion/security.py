"""
security.py — HMAC signing/verification and IP allow-list validation.

All security primitives live here so they can be imported by both
the file ingestor and the HTTP ingestor without duplication.

Security model
--------------
* HMAC-SHA256 is used to authenticate webhook payloads.
  The shared secret is loaded from the environment — never hardcoded.
* IP validation restricts which hosts may push events to the HTTP endpoint.
* Constant-time comparison (hmac.compare_digest) prevents timing attacks.
"""

import hashlib
import hmac
import ipaddress
import logging
import os
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — loaded once at import time
# ---------------------------------------------------------------------------

# Force disable HMAC for development (set to False for production)
FORCE_DISABLE_HMAC = os.environ.get("FORCE_DISABLE_HMAC", "true").lower() == "true"

# The shared HMAC secret.  Must be set in the environment or .env file.
_SECRET: bytes = os.environ.get("HMAC_SECRET", "").encode()

# Comma-separated list of allowed source IPs, e.g. "10.0.0.1,192.168.1.5"
# An empty string means "allow all" — suitable only for dev environments.
_ALLOWED_IPS_RAW: str = os.environ.get("ALLOWED_IPS", "")


def _load_allowed_ips() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Parse ALLOWED_IPS into a list of ip_network objects.
    Supports both single IPs ("10.0.0.1") and CIDR ranges ("10.0.0.0/24").
    Returns an empty list when ALLOWED_IPS is not set → allow all.
    """
    if not _ALLOWED_IPS_RAW.strip():
        return []  # Open — caller should check for prod deployments
    networks = []
    for entry in _ALLOWED_IPS_RAW.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            log.warning("Invalid entry in ALLOWED_IPS: %r — skipping", entry)
    return networks


_ALLOWED_NETWORKS = _load_allowed_ips()


# ---------------------------------------------------------------------------
# HMAC helpers
# ---------------------------------------------------------------------------

def sign_payload(payload: bytes) -> str:
    """
    Compute an HMAC-SHA256 hex digest for *payload* using the shared secret.

    Used by internal services that need to attach a signature before
    forwarding events (e.g., the Honeytrap pusher → HTTP ingestor path).

    Args:
        payload: Raw bytes to sign (typically the JSON body).

    Returns:
        Lowercase hex string of the HMAC digest.

    Raises:
        RuntimeError: If HMAC_SECRET is not configured.
    """
    if not _SECRET:
        raise RuntimeError("HMAC_SECRET is not set — cannot sign payload")
    return hmac.new(_SECRET, payload, hashlib.sha256).hexdigest()


def verify_signature(payload: bytes, provided_sig: str) -> bool:
    """
    Verify that *provided_sig* matches the HMAC-SHA256 of *payload*.

    Uses hmac.compare_digest for constant-time comparison to resist
    timing side-channel attacks.

    Args:
        payload:      Raw request body bytes.
        provided_sig: Hex digest from the X-Honeytrap-Signature header.

    Returns:
        True if the signature is valid; False otherwise.
    """
    # Force disable HMAC for development
    if FORCE_DISABLE_HMAC:
        log.debug("HMAC verification disabled (development mode)")
        return True

    if not _SECRET:
        log.error("HMAC_SECRET not set — rejecting all signatures for safety")
        return False

    if not provided_sig:
        log.warning("No signature provided")
        return False

    expected = hmac.new(_SECRET, payload, hashlib.sha256).hexdigest()

    # Strip optional "sha256=" prefix (GitHub-style signatures)
    provided_clean = provided_sig.removeprefix("sha256=")

    valid = hmac.compare_digest(expected, provided_clean.lower())
    if not valid:
        log.warning("HMAC mismatch — payload may be tampered or secret wrong")
    return valid


# ---------------------------------------------------------------------------
# IP validation helper
# ---------------------------------------------------------------------------

def is_ip_allowed(client_ip: str) -> bool:
    """
    Check whether *client_ip* is in the ALLOWED_IPS allow-list.

    If ALLOWED_IPS is empty, all IPs are allowed (development mode).
    Log a warning in that case so operators notice.

    Args:
        client_ip: IPv4 or IPv6 address string from the request.

    Returns:
        True if the IP is permitted; False otherwise.
    """
    if not _ALLOWED_NETWORKS:
        log.debug("ALLOWED_IPS not configured — allowing all IPs (dev mode)")
        return True

    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        log.warning("Could not parse client IP: %r", client_ip)
        return False

    for network in _ALLOWED_NETWORKS:
        if addr in network:
            return True

    log.warning("Blocked request from disallowed IP: %s", client_ip)
    return False


# ---------------------------------------------------------------------------
# Convenience: validate both IP and signature in one call
# ---------------------------------------------------------------------------

def validate_request(
    client_ip: str,
    payload: bytes,
    provided_sig: Optional[str],
) -> tuple[bool, str]:
    """
    Run IP check then HMAC check.  Returns (ok, reason) so callers can
    return a specific HTTP error message to the client.

    Args:
        client_ip:    Source IP address.
        payload:      Raw request body bytes.
        provided_sig: Value of the X-Honeytrap-Signature header (may be None).

    Returns:
        (True, "") on success.
        (False, human-readable reason) on failure.
    """
    if not is_ip_allowed(client_ip):
        return False, f"IP {client_ip} is not in the allow-list"

    if not verify_signature(payload, provided_sig or ""):
        return False, "Invalid or missing HMAC signature"

    return True, ""