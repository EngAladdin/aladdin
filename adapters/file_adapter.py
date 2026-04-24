"""
adapters/file_adapter.py — Adapter that reads events from a JSONL file.

Why adapters?
-------------
Adapters decouple the *source* of events from the normalization / queuing
pipeline.  Adding a new source (Kafka, Elasticsearch, syslog …) means writing
a new adapter — not touching the core ingestor logic.

This adapter wraps the file-tail ingestor and exposes a clean interface
that higher-level orchestrators can call.
"""

import json
import logging
import os
from collections.abc import Generator
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_FILE_PATH: str = os.environ.get("LOG_FILE_PATH", "/var/log/honeytrap/events.jsonl")


class FileAdapter:
    """
    Reads Honeytrap JSONL events from a log file.

    Supports two modes:
    * Batch (read_all)  — read the whole file once and return all events.
    * Stream (stream)   — yield events one by one; useful for testing pipelines.

    The tail-follow behaviour (for production) is implemented in
    file_tail_ingest.py which calls normalize() / push_event() directly.
    This adapter is the testable / composable unit.
    """

    def __init__(self, file_path: str = DEFAULT_FILE_PATH) -> None:
        self.file_path = file_path

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def read_all(self) -> list[dict[str, Any]]:
        """
        Open the file, parse every JSONL line, and return a list of dicts.
        Invalid lines are skipped with a warning — never raise.
        """
        events: list[dict] = []
        try:
            with open(self.file_path, encoding="utf-8", errors="replace") as fh:
                for line_num, line in enumerate(fh, start=1):
                    event = self._parse_line(line, line_num)
                    if event is not None:
                        events.append(event)
        except FileNotFoundError:
            log.error("File not found: %s", self.file_path)
        except OSError as exc:
            log.error("Cannot read file %s: %s", self.file_path, exc)

        log.info("FileAdapter: read %d events from %s", len(events), self.file_path)
        return events

    def stream(self) -> Generator[dict[str, Any], None, None]:
        """
        Yield events one at a time from the file.
        Memory-efficient for large files.
        """
        try:
            with open(self.file_path, encoding="utf-8", errors="replace") as fh:
                for line_num, line in enumerate(fh, start=1):
                    event = self._parse_line(line, line_num)
                    if event is not None:
                        yield event
        except FileNotFoundError:
            log.error("File not found: %s", self.file_path)
        except OSError as exc:
            log.error("Cannot stream file %s: %s", self.file_path, exc)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_line(line: str, line_num: int) -> dict[str, Any] | None:
        """Parse a single JSONL line.  Returns None on parse failure."""
        line = line.strip()
        if not line:
            return None  # blank line — skip silently
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("Line %d: JSON parse error: %s | raw=%r", line_num, exc, line[:120])
            return None
