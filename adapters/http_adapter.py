"""
adapters/http_adapter.py — Adapter that POSTs events to the HTTP ingest endpoint.

Use case
--------
Some Honeytrap deployments cannot write to a shared filesystem.  This adapter
lets any internal service (or Honeytrap itself, via a custom pusher) forward
events to the HTTP ingestor over the network — with HMAC signatures attached.

It is also used in integration tests to simulate webhook deliveries.
"""

import json
import logging
import os
import time
from typing import Any, Optional

import requests
from requests.exceptions import RequestException

from ingestion.security import sign_payload

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

INGEST_URL: str  = os.environ.get("INGEST_HTTP_URL", "http://localhost:8000/ingest/event")
MAX_RETRIES: int = int(os.environ.get("HTTP_ADAPTER_MAX_RETRIES", "3"))
TIMEOUT:     float = float(os.environ.get("HTTP_ADAPTER_TIMEOUT", "5.0"))  # seconds
INITIAL_DELAY: float = 1.0
BACKOFF_FACTOR: float = 2.0
MAX_DELAY: float = 15.0


class HttpAdapter:
    """
    Sends Honeytrap events to the HTTP ingestor endpoint.

    Automatically:
    * Serializes the payload to JSON.
    * Signs the body with HMAC-SHA256 (X-Honeytrap-Signature header).
    * Retries on transient network/server errors with exponential backoff.
    """

    def __init__(
        self,
        url: str = INGEST_URL,
        max_retries: int = MAX_RETRIES,
        timeout: float = TIMEOUT,
    ) -> None:
        self.url = url
        self.max_retries = max_retries
        self.timeout = timeout
        # Persistent session reuses TCP connections for efficiency
        self._session = requests.Session()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def send(self, event: dict[str, Any]) -> bool:
        """
        POST a single event dict to the ingest endpoint.

        Args:
            event: Raw Honeytrap event dict (pre-normalization).

        Returns:
            True if the server accepted the event (2xx); False otherwise.
        """
        return self._post_with_retry([event])

    def send_batch(self, events: list[dict[str, Any]]) -> bool:
        """
        POST a batch of events in a single request.
        The ingest endpoint accepts both a single dict and a list.

        Args:
            events: List of raw Honeytrap event dicts.

        Returns:
            True if the server accepted the batch; False otherwise.
        """
        if not events:
            log.debug("HttpAdapter.send_batch called with empty list — skipping")
            return True
        return self._post_with_retry(events)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_headers(self, body: bytes) -> dict[str, str]:
        """Build request headers including the HMAC signature."""
        try:
            sig = sign_payload(body)
            signature_header = f"sha256={sig}"
        except RuntimeError as exc:
            # HMAC_SECRET not set — log and send without signature
            # (server will reject unless ALLOWED_IPS is open)
            log.warning("Could not sign payload: %s — sending unsigned", exc)
            signature_header = ""

        return {
            "Content-Type":          "application/json",
            "X-Honeytrap-Signature": signature_header,
            "User-Agent":            "cerebrum-http-adapter/1.0",
        }

    def _post_with_retry(self, payload: Any) -> bool:
        """
        Serialize payload and POST to self.url, retrying on transient failures.
        """
        try:
            body = json.dumps(payload, default=str).encode()
        except (TypeError, ValueError) as exc:
            log.error("Cannot serialize payload to JSON: %s", exc)
            return False

        headers = self._build_headers(body)
        delay   = INITIAL_DELAY

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._session.post(
                    self.url,
                    data=body,
                    headers=headers,
                    timeout=self.timeout,
                )

                if resp.ok:  # 2xx
                    log.debug(
                        "HttpAdapter: sent %d event(s) → %s (HTTP %d)",
                        len(payload) if isinstance(payload, list) else 1,
                        self.url,
                        resp.status_code,
                    )
                    return True

                # 4xx = client error — don't retry (won't help)
                if 400 <= resp.status_code < 500:
                    log.error(
                        "HttpAdapter: server rejected payload (HTTP %d): %s",
                        resp.status_code,
                        resp.text[:300],
                    )
                    return False

                # 5xx — server-side transient error, retry
                log.warning(
                    "HttpAdapter: server error (attempt %d/%d, HTTP %d) — retrying in %.1fs",
                    attempt,
                    self.max_retries,
                    resp.status_code,
                    delay,
                )

            except RequestException as exc:
                log.warning(
                    "HttpAdapter: network error (attempt %d/%d): %s — retrying in %.1fs",
                    attempt,
                    self.max_retries,
                    exc,
                    delay,
                )

            if attempt < self.max_retries:
                time.sleep(delay)
                delay = min(delay * BACKOFF_FACTOR, MAX_DELAY)

        log.error("HttpAdapter: gave up after %d attempts → %s", self.max_retries, self.url)
        return False

    def close(self) -> None:
        """Release the underlying TCP connections."""
        self._session.close()

    # Allow use as a context manager: `with HttpAdapter() as a: a.send(evt)`
    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
