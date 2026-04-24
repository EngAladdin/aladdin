"""
file_tail_ingest.py — Tail a Honeytrap JSONL log file and push events to Redis.

How it works
------------
1. Opens the log file at LOG_FILE_PATH (set via env or CLI arg).
2. Seeks to the end of the file (like `tail -f`) so we only process new lines.
3. For each new line: parse JSON → normalize → push to Redis queue.
4. If the file is rotated (size shrinks / inode changes), it reopens it.
5. Runs forever until killed (SIGINT / SIGTERM are handled gracefully).

Usage
-----
    python -m ingestion.file_tail_ingest                    # uses env LOG_FILE_PATH
    python -m ingestion.file_tail_ingest /var/log/ht.jsonl  # or pass path directly
"""

import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Optional

# Sibling modules
from ingestion.normalize import normalize
from ingestion.queue import push_event

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("file_tail_ingest")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_FILE_PATH: str = os.environ.get("LOG_FILE_PATH", "/var/log/honeytrap/events.jsonl")
POLL_INTERVAL: float = float(os.environ.get("POLL_INTERVAL", "0.5"))  # seconds between reads
SEEK_TO_END:   bool  = os.environ.get("TAIL_FROM_END", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
_running = True

def _handle_signal(sig, frame):  # noqa: ANN001
    global _running
    log.info("Received signal %s — shutting down gracefully …", sig)
    _running = False

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------

def _open_file(path: str):
    """
    Open the log file.  If SEEK_TO_END is True, move the cursor to the end
    so we only process lines written after startup (tail behaviour).
    If the file doesn't exist yet, wait until it appears.
    """
    while _running:
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
            if SEEK_TO_END:
                fh.seek(0, 2)  # 0 bytes from EOF
                log.info("Opened %s — tailing from end (offset %d)", path, fh.tell())
            else:
                log.info("Opened %s — reading from beginning", path)
            return fh
        except FileNotFoundError:
            log.warning("Log file not found: %s — waiting …", path)
            time.sleep(2)
    return None


def _file_changed(fh, path: str) -> bool:
    """
    Detect log rotation: the file shrank (rolled) or the inode changed.
    Returns True if we should reopen the file.
    """
    try:
        current_stat = os.stat(path)
        fh_stat = os.fstat(fh.fileno())
        return (
            current_stat.st_ino != fh_stat.st_ino  # inode changed (rotation)
            or current_stat.st_size < fh.tell()    # file truncated / reset
        )
    except OSError:
        return True  # File disappeared — treat as changed


def _process_line(line: str, line_num: int) -> None:
    """
    Parse one JSONL line, normalize it, and push to Redis.
    Errors are logged but never propagate (ingestor must not crash).
    """
    line = line.strip()
    if not line:
        return  # blank / empty line

    # --- Parse JSON ---
    try:
        raw_event = json.loads(line)
    except json.JSONDecodeError as exc:
        log.warning("Line %d is not valid JSON: %s | raw=%r", line_num, exc, line[:200])
        return

    # --- Normalize ---
    normalized = normalize(raw_event)
    if normalized is None:
        log.warning("Line %d failed normalization — skipping", line_num)
        return

    # --- Queue ---
    ok = push_event(normalized)
    if not ok:
        log.error("Line %d: failed to queue event %s", line_num, normalized.get("event_id"))


def tail_file(path: str) -> None:
    """
    Main loop: open the file and continuously read new lines.
    Reopens automatically on log rotation.
    """
    log.info("Starting file tail ingestor → %s", path)
    fh: Optional[object] = None
    line_num = 0

    while _running:
        # (Re)open file if needed
        if fh is None:
            fh = _open_file(path)
            if fh is None:
                break  # shutdown requested while waiting for file

        # Read all available lines
        while _running:
            line = fh.readline()
            if not line:
                break  # no new data yet — go back to poll sleep
            line_num += 1
            _process_line(line, line_num)

        # Check for log rotation before sleeping
        if fh and _file_changed(fh, path):
            log.info("Log rotation detected — reopening %s", path)
            fh.close()
            fh = None
            continue

        time.sleep(POLL_INTERVAL)

    if fh:
        fh.close()
    log.info("File tail ingestor stopped. Processed %d lines.", line_num)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE_PATH
    if not Path(path).parent.exists():
        log.warning("Parent directory of log file does not exist: %s", Path(path).parent)
    tail_file(path)


if __name__ == "__main__":
    main()
