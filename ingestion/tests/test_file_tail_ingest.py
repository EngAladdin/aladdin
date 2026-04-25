"""
test_file_tail_ingest.py — Unit tests for ingestion/file_tail_ingest.py.

Run with:
    pytest ingestion/tests/test_file_tail_ingest.py -v
"""

import pytest
import json
import os
import tempfile
import time
import threading
from unittest.mock import patch, Mock
from ingestion import file_tail_ingest


class TestFileTailIngest:
    """Test file tail ingestor."""
    
    def test_process_line_valid_json(self, mock_redis):
        """Should process valid JSON line."""
        with patch('ingestion.file_tail_ingest.push_event') as mock_push:
            mock_push.return_value = True
            
            line = '{"eventid":"test","src_ip":"1.1.1.1","sensor":"test"}\n'
            file_tail_ingest._process_line(line, 1)
            
            mock_push.assert_called_once()
    
    def test_process_line_invalid_json(self, mock_redis):
        """Should skip invalid JSON lines."""
        with patch('ingestion.file_tail_ingest.push_event') as mock_push:
            line = "not valid json\n"
            file_tail_ingest._process_line(line, 1)
            
            mock_push.assert_not_called()
    
    def test_process_line_empty_line(self, mock_redis):
        """Should skip empty lines."""
        with patch('ingestion.file_tail_ingest.push_event') as mock_push:
            file_tail_ingest._process_line("", 1)
            file_tail_ingest._process_line("\n", 2)
            file_tail_ingest._process_line("   \n", 3)
            
            mock_push.assert_not_called()
    
    def test_file_changed_detection_rotation(self):
        """Should detect file rotation by inode change."""
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"test\n")
            f.flush()
            
            with open(f.name, 'r') as fh:
                # Same file, should not be changed
                assert not file_tail_ingest._file_changed(fh, f.name)
            
            # Create new file with same name (simulate rotation)
            os.unlink(f.name)
            with open(f.name, 'w') as f2:
                f2.write("new file\n")
            
            with open(f.name, 'r') as fh2:
                # Should detect change
                assert file_tail_ingest._file_changed(fh2, f.name)
    
    def test_file_changed_detection_truncated(self):
        """Should detect file truncation."""
        with tempfile.NamedTemporaryFile(mode='w+') as f:
            f.write("multiple lines of text\n")
            f.write("more content here\n")
            f.flush()
            
            f.seek(0)
            with open(f.name, 'r') as fh:
                # Read some content to advance position
                fh.read(10)
                original_pos = fh.tell()
                
                # Truncate file
                f.truncate(5)
                f.flush()
                
                # Should detect truncation
                assert file_tail_ingest._file_changed(fh, f.name)
    
    def test_open_file_exists(self):
        """Should open existing file."""
        with tempfile.NamedTemporaryFile(mode='w') as f:
            f.write("test\n")
            f.flush()
            
            fh = file_tail_ingest._open_file(f.name)
            assert fh is not None
            fh.close()
    
    def test_open_file_not_exists(self):
        """Should wait for file to appear."""
        nonexistent = "/tmp/nonexistent_file_12345.txt"
        
        # Start thread to create file after delay
        def create_file():
            time.sleep(1)
            with open(nonexistent, 'w') as f:
                f.write("created\n")
        
        thread = threading.Thread(target=create_file)
        thread.start()
        
        # Mock _running to stop after timeout
        original_running = file_tail_ingest._running
        file_tail_ingest._running = True
        
        try:
            start = time.time()
            fh = file_tail_ingest._open_file(nonexistent)
            elapsed = time.time() - start
            
            assert fh is not None
            assert elapsed >= 1.0
            fh.close()
        finally:
            file_tail_ingest._running = original_running
            if os.path.exists(nonexistent):
                os.unlink(nonexistent)
    
    def test_shutdown_signal_handler(self):
        """Should handle shutdown signals gracefully."""
        import signal
        
        # Mock _running
        file_tail_ingest._running = True
        file_tail_ingest._handle_signal(signal.SIGINT, None)
        
        assert file_tail_ingest._running is False
