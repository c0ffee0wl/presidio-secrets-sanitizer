#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Presidio + secrets-patterns-db Integration Script
Robust version with temp directory for all state files
"""
import argparse
import json
import logging
import re
import sys
import time
import yaml
import asyncio
import os
import struct
import signal
import platform
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

# Import Windows-specific module if on Windows
if platform.system() == 'Windows':
    try:
        import msvcrt
        HAS_MSVCRT = True
    except ImportError:
        HAS_MSVCRT = False
else:
    HAS_MSVCRT = False

# Import watchdog for file watching functionality
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import requests
import tempfile
from dataclasses import dataclass, asdict
import aiofiles
import uuid
import hashlib
import threading
import atexit
from contextlib import asynccontextmanager

# Presidio imports
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerRegistry
from presidio_anonymizer import AnonymizerEngine, OperatorConfig
from presidio_anonymizer.operators import Operator, OperatorType
from presidio_anonymizer.entities import RecognizerResult

@dataclass
class ProcessingStats:
    """Statistics for processing operations."""
    lines_processed: int = 0
    lines_with_findings: int = 0
    entities_found: int = 0
    secrets_found: int = 0
    errors: int = 0
    processing_time: float = 0.0

class RobustSequenceManager:
    """Manages global sequence numbers with recovery and validation - TEMP FILES ONLY."""
    
    def __init__(self, output_file: Path):
        # Create temp directory for this output file's state
        self.temp_dir = Path(tempfile.gettempdir()) / "presidio-state" / hashlib.md5(str(output_file.resolve()).encode()).hexdigest()[:16]
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        self.sequence_file = self.temp_dir / "sequence"
        self.lock_file = self.temp_dir / "sequence.lock"
        self.logger = logging.getLogger(__name__)
        self.is_windows = platform.system() == 'Windows'
        
        self._ensure_files()
        atexit.register(self._cleanup)
    
    def _cleanup(self):
        """Cleanup temp files on exit."""
        try:
            if self.lock_file.exists():
                self.lock_file.unlink()
            # Optionally clean up sequence file too
            # if self.sequence_file.exists():
            #     self.sequence_file.unlink()
        except:
            pass
    
    def _ensure_files(self):
        try:
            if not self.sequence_file.exists():
                with open(self.sequence_file, 'wb') as f:
                    f.write(struct.pack('Q', 0))
                    f.flush()
                    if hasattr(os, 'fsync'):
                        os.fsync(f.fileno())
                self.logger.debug(f"Created sequence file: {self.sequence_file}")
            else:
                self._validate_sequence_file()
        except Exception as e:
            self.logger.error(f"Failed to setup sequence file: {e}")
            raise
    
    def _validate_sequence_file(self):
        try:
            with open(self.sequence_file, 'rb') as f:
                data = f.read()
                if len(data) != 8:
                    self.logger.warning(f"Invalid sequence file size: {len(data)}, recreating")
                    with open(self.sequence_file, 'wb') as fix_f:
                        fix_f.write(struct.pack('Q', 0))
                        fix_f.flush()
                        if hasattr(os, 'fsync'):
                            os.fsync(fix_f.fileno())
        except Exception as e:
            self.logger.error(f"Error validating sequence file: {e}")
            raise
    
    def _acquire_file_lock(self, f):
        """Cross-platform file locking."""
        if HAS_FCNTL and not self.is_windows:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif self.is_windows and HAS_MSVCRT:
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
    
    def _release_file_lock(self, f):
        """Cross-platform file lock release."""
        if HAS_FCNTL and not self.is_windows:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        elif self.is_windows and HAS_MSVCRT:
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    
    def get_next_sequence(self) -> int:
        max_retries = 100
        base_delay = 0.001
        
        for attempt in range(max_retries):
            try:
                lock_acquired = False
                lock_start = time.time()
                
                while (time.time() - lock_start) < 5.0:
                    try:
                        if self.is_windows:
                            # Windows doesn't support O_EXCL reliably, use different approach
                            if not self.lock_file.exists():
                                with open(self.lock_file, 'w') as lf:
                                    lf.write(f"{os.getpid()}\n{time.time()}\n{attempt}\n")
                                lock_acquired = True
                                lock_fd = None
                                break
                        else:
                            # Use os.open with Unix-specific flags
                            if hasattr(os, 'O_CREAT') and hasattr(os, 'O_EXCL') and hasattr(os, 'O_WRONLY'):
                                lock_fd = os.open(str(self.lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                                lock_acquired = True
                                break
                            else:
                                # Fallback for systems without these flags
                                if not self.lock_file.exists():
                                    with open(self.lock_file, 'w') as lf:
                                        lf.write(f"{os.getpid()}\n{time.time()}\n{attempt}\n")
                                    lock_acquired = True
                                    lock_fd = None
                                    break
                    except (FileExistsError, OSError):
                        await_time = base_delay * (attempt + 1)
                        time.sleep(min(await_time, 0.1))
                    except Exception:
                        break
                
                if not lock_acquired:
                    continue
                
                try:
                    if not self.is_windows and lock_fd is not None:
                        lock_info = f"{os.getpid()}\n{time.time()}\n{attempt}\n".encode()
                        os.write(lock_fd, lock_info)
                        if hasattr(os, 'fsync'):
                            os.fsync(lock_fd)
                    
                    with open(self.sequence_file, 'r+b') as f:
                        try:
                            self._acquire_file_lock(f)
                        except (OSError, IOError):
                            # If file locking fails, continue without it (less safe but functional)
                            pass
                        
                        try:
                            f.seek(0)
                            data = f.read(8)
                            if len(data) == 8:
                                current_seq = struct.unpack('Q', data)[0]
                            else:
                                current_seq = 0
                            
                            if current_seq > 1000000:
                                current_seq = 0
                            
                            next_seq = current_seq + 1
                            f.seek(0)
                            f.write(struct.pack('Q', next_seq))
                            f.flush()
                            if hasattr(os, 'fsync'):
                                os.fsync(f.fileno())
                            
                            return current_seq
                            
                        finally:
                            try:
                                self._release_file_lock(f)
                            except (OSError, IOError):
                                pass
                            
                finally:
                    try:
                        if not self.is_windows and lock_fd is not None:
                            os.close(lock_fd)
                        if self.lock_file.exists():
                            self.lock_file.unlink()
                    except:
                        pass
                        
            except Exception as e:
                delay = min(base_delay * (2 ** attempt), 1.0)
                if attempt < max_retries - 1:
                    time.sleep(delay)
        
        raise RuntimeError(f"Failed to get sequence after {max_retries} attempts")

class RobustOrderedFileWriter:
    """Writes to file in global sequence order - CLEAN OUTPUT, TEMP STATE FILES."""
    
    def __init__(self, output_file: Path):
        self.output_file = output_file
        
        # Create temp directory for this output file's state
        self.temp_dir = Path(tempfile.gettempdir()) / "presidio-state" / hashlib.md5(str(output_file.resolve()).encode()).hexdigest()[:16]
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        self.written_file = self.temp_dir / "written"
        self.pending_writes: Dict[int, tuple] = {}
        self.next_write_seq = 0
        self.logger = logging.getLogger(__name__)
        self.is_windows = platform.system() == 'Windows'
        
        self.written_sequences: Set[int] = set()
        self.max_wait_time = 300.0
        self.write_lock = threading.Lock()
        
        self._load_written_state()
        atexit.register(self._cleanup)
    
    def _cleanup(self):
        """Cleanup temp files on exit."""
        try:
            # Optionally clean up written file
            # if self.written_file.exists():
            #     self.written_file.unlink()
            pass
        except:
            pass
    
    def _acquire_file_lock(self, f, shared=False):
        """Cross-platform file locking."""
        if HAS_FCNTL and not self.is_windows:
            lock_type = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
            fcntl.flock(f.fileno(), lock_type)
        elif self.is_windows and HAS_MSVCRT:
            # Windows file locking is always exclusive
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
    
    def _release_file_lock(self, f):
        """Cross-platform file lock release."""
        if HAS_FCNTL and not self.is_windows:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        elif self.is_windows and HAS_MSVCRT:
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    
    def _load_written_state(self):
        try:
            if self.written_file.exists():
                with open(self.written_file, 'rb') as f:
                    try:
                        self._acquire_file_lock(f, shared=True)
                    except (OSError, IOError):
                        # Continue without locking if it fails
                        pass
                    
                    try:
                        data = f.read()
                        if len(data) >= 8:
                            self.next_write_seq = struct.unpack('Q', data[:8])[0]
                            
                            if len(data) > 8:
                                try:
                                    json_data = data[8:].decode('utf-8')
                                    written_list = json.loads(json_data)
                                    self.written_sequences = set(written_list)
                                except:
                                    self.written_sequences = set()
                            
                            self.logger.debug(f"Loaded next_write_seq: {self.next_write_seq}")
                        else:
                            self._save_written_state(0)
                    finally:
                        try:
                            self._release_file_lock(f)
                        except (OSError, IOError):
                            pass
            else:
                self._save_written_state(0)
                
        except Exception as e:
            self.logger.warning(f"Could not load written state: {e}")
            self.next_write_seq = 0
            self.written_sequences = set()
    
    def _save_written_state(self, seq: int):
        try:
            temp_written = self.written_file.with_suffix('.tmp')
            with open(temp_written, 'wb') as f:
                f.write(struct.pack('Q', seq))
                written_list = sorted(list(self.written_sequences))
                json_data = json.dumps(written_list).encode('utf-8')
                f.write(json_data)
                f.flush()
                if hasattr(os, 'fsync'):
                    os.fsync(f.fileno())
            
            # Atomic rename works on both Unix and Windows
            temp_written.replace(self.written_file)
            
        except Exception as e:
            self.logger.error(f"Could not save written state: {e}")
    
    async def queue_for_writing(self, seq_num: int, content: str, metadata: str):
        """Queue content with robust error handling."""
        with self.write_lock:
            if seq_num in self.written_sequences:
                self.logger.warning(f"Sequence {seq_num} already written, skipping")
                return
            
            self.pending_writes[seq_num] = (content, metadata, time.time(), 0)
            self.logger.debug(f"Queued sequence {seq_num} for writing")
        
        await self._attempt_write_sequences()
    
    async def _attempt_write_sequences(self):
        """Write consecutive sequences - CLEAN CONTENT ONLY."""
        if not self.pending_writes:
            return
        
        try:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.output_file, 'a', encoding='utf-8') as f:
                try:
                    self._acquire_file_lock(f)
                except (OSError, IOError):
                    # Continue without locking if it fails
                    pass
                
                try:
                    self._load_written_state()
                    
                    written_count = 0
                    max_writes = 100
                    
                    while written_count < max_writes and self.next_write_seq in self.pending_writes:
                        seq_num = self.next_write_seq
                        content, metadata, queue_time, retries = self.pending_writes.pop(seq_num)
                        
                        try:
                            # Write ONLY the clean content - no metadata
                            f.write(content)
                            f.flush()
                            
                            self.written_sequences.add(seq_num)
                            self.next_write_seq += 1
                            written_count += 1
                            
                            wait_time = time.time() - queue_time
                            self.logger.info(f"Wrote sequence {seq_num}: {metadata} (waited {wait_time:.2f}s)")
                            
                        except Exception as e:
                            self.logger.error(f"Error writing sequence {seq_num}: {e}")
                            if retries < 3:
                                self.pending_writes[seq_num] = (content, metadata, queue_time, retries + 1)
                            break
                    
                    if written_count > 0:
                        if hasattr(os, 'fsync'):
                            os.fsync(f.fileno())
                        self._save_written_state(self.next_write_seq)
                    
                finally:
                    try:
                        self._release_file_lock(f)
                    except (OSError, IOError):
                        pass
                    
        except Exception as e:
            self.logger.error(f"Error in write attempt: {e}")
    
    async def finalize_remaining(self, timeout: float = None):
        """Finalize remaining writes with timeout."""
        if timeout is None:
            timeout = self.max_wait_time
        
        start_time = time.time()
        last_log_time = start_time
        
        while self.pending_writes and (time.time() - start_time) < timeout:
            await self._attempt_write_sequences()
            
            if self.pending_writes:
                current_time = time.time()
                
                if current_time - last_log_time > 10.0:
                    pending_count = len(self.pending_writes)
                    min_pending = min(self.pending_writes.keys()) if self.pending_writes else None
                    elapsed = current_time - start_time
                    
                    self.logger.info(f"Waiting for sequence {self.next_write_seq}, "
                                   f"pending: {pending_count} (min: {min_pending}), "
                                   f"elapsed: {elapsed:.1f}s")
                    
                    last_log_time = current_time
                
                await asyncio.sleep(0.2)
        
        # Force write remaining out of order
        if self.pending_writes:
            elapsed = time.time() - start_time
            self.logger.warning(f"Timeout after {elapsed:.1f}s, force-writing {len(self.pending_writes)} out-of-order sequences")
            
            await self._force_write_remaining()
    
    async def _force_write_remaining(self):
        """Force write remaining sequences - CLEAN CONTENT ONLY."""
        try:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                try:
                    self._acquire_file_lock(f)
                except (OSError, IOError):
                    pass
                
                try:
                    for seq_num in sorted(self.pending_writes.keys()):
                        content, metadata, queue_time, retries = self.pending_writes[seq_num]
                        
                        # Write ONLY clean content, no metadata about out-of-order
                        f.write(content)
                        
                        self.logger.warning(f"Force-wrote sequence {seq_num}: {metadata}")
                    
                    f.flush()
                    if hasattr(os, 'fsync'):
                        os.fsync(f.fileno())
                    
                finally:
                    try:
                        self._release_file_lock(f)
                    except (OSError, IOError):
                        pass
                    
            self.pending_writes.clear()
            
        except Exception as e:
            self.logger.error(f"Error force-writing remaining sequences: {e}")

class RobustAsyncLineProcessor:
    """Robust async line processor with clean output."""
    
    def __init__(self, integrator, output_file: Optional[Path] = None, sequence_num: Optional[int] = None):
        self.integrator = integrator
        self.output_file = output_file
        self.sequence_num = sequence_num
        self.logger = logging.getLogger(__name__)
        self.file_writer = RobustOrderedFileWriter(output_file) if output_file else None
        
        self.instance_id = f"pid_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        self.start_time = time.time()
        
        self.stdin_closed = False
        self.processing_cancelled = False
        
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown")
            self.processing_cancelled = True
        
        try:
            # SIGINT (Ctrl+C) is available on both Unix and Windows
            signal.signal(signal.SIGINT, signal_handler)
            
            # SIGTERM is Unix-only, only set if available
            if hasattr(signal, 'SIGTERM'):
                signal.signal(signal.SIGTERM, signal_handler)
            
            # Windows-specific signals
            if platform.system() == 'Windows':
                if hasattr(signal, 'SIGBREAK'):
                    signal.signal(signal.SIGBREAK, signal_handler)
        except Exception as e:
            self.logger.warning(f"Could not setup signal handlers: {e}")
    
    async def read_stdin_robust(self) -> List[str]:
        """Read stdin with robust error handling."""
        try:
            if sys.stdin.isatty():
                self.logger.error("No stdin data available (running in TTY)")
                return []
            
            try:
                loop = asyncio.get_event_loop()
                reader = asyncio.StreamReader()
                protocol = asyncio.StreamReaderProtocol(reader)
                transport, _ = await asyncio.wait_for(
                    loop.connect_read_pipe(lambda: protocol, sys.stdin),
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                self.logger.error("Timeout setting up stdin reader")
                return []
            
            lines = []
            line_count = 0
            
            try:
                while not self.processing_cancelled:
                    try:
                        line_bytes = await asyncio.wait_for(reader.readline(), timeout=60.0)
                        
                        if not line_bytes:
                            break
                        
                        line = line_bytes.decode('utf-8', errors='replace').rstrip('\r\n')
                        lines.append(line)
                        line_count += 1
                        
                        if line_count > 1000000:
                            self.logger.error(f"Too many input lines: {line_count}, stopping")
                            break
                        
                        if len(line) > 100000:
                            self.logger.warning(f"Very long line ({len(line)} chars) on line {line_count}")
                        
                        if line_count % 5000 == 0:
                            self.logger.debug(f"Read {line_count} lines")
                        
                    except asyncio.TimeoutError:
                        self.logger.warning("Timeout reading from stdin, assuming EOF")
                        break
                    except UnicodeDecodeError:
                        lines.append("")  # Empty line for decode errors
                        continue
                        
            finally:
                transport.close()
                self.stdin_closed = True
            
            input_hash = hashlib.md5('\n'.join(lines).encode('utf-8', errors='replace')).hexdigest()[:8]
            
            self.logger.info(f"Read complete [seq={self.sequence_num}, instance={self.instance_id}]: "
                           f"{len(lines)} lines, hash={input_hash}")
            
            return lines
            
        except Exception as e:
            self.logger.error(f"Error reading stdin: {e}")
            return []
    
    async def process_line_robust(self, line: str, line_index: int) -> str:
        """Process single line with error recovery."""
        try:
            if not line.strip():
                return line
            
            if self.processing_cancelled:
                return line
            
            loop = asyncio.get_event_loop()
            
            try:
                analyzer_results = await asyncio.wait_for(
                    loop.run_in_executor(None, self.integrator.analyze_text, line),
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"Analyzer timeout on line {line_index}")
                self.integrator.stats.errors += 1
                return line
            
            self.integrator.stats.lines_processed += 1
            
            if analyzer_results:
                self.integrator.stats.lines_with_findings += 1
                self.integrator.stats.entities_found += len(analyzer_results)
                
                try:
                    processed_line = await asyncio.wait_for(
                        loop.run_in_executor(None, self.integrator.pseudonymize_text, line, analyzer_results),
                        timeout=30.0
                    )
                    return processed_line
                except asyncio.TimeoutError:
                    self.logger.warning(f"Pseudonymizer timeout on line {line_index}")
                    self.integrator.stats.errors += 1
                    return line
            else:
                return line
                
        except Exception as e:
            self.logger.error(f"Error processing line {line_index}: {e}")
            self.integrator.stats.errors += 1
            return line
    
    async def process_stdin_stream_robust(self):
        """Main processing with clean output."""
        self.logger.info(f"Starting processing [seq={self.sequence_num}, instance={self.instance_id}] -> {self.output_file or 'stdout'}")
        
        try:
            input_lines = await self.read_stdin_robust()
            
            if self.processing_cancelled:
                self.logger.info(f"Processing cancelled during input [seq={self.sequence_num}]")
                return
            
            if not input_lines:
                self.logger.info(f"No input received [seq={self.sequence_num}, instance={self.instance_id}]")
                
                # Write empty content to maintain sequence - NO METADATA
                if self.file_writer and self.sequence_num is not None:
                    content = ""  # Completely empty
                    metadata = f"instance={self.instance_id}, 0 lines"
                    await self.file_writer.queue_for_writing(self.sequence_num, content, metadata)
                    await self.file_writer.finalize_remaining(timeout=30.0)
                return
            
            # Process lines
            processed_lines = []
            
            for i, line in enumerate(input_lines):
                if self.processing_cancelled:
                    self.logger.warning(f"Processing cancelled at line {i+1}/{len(input_lines)}")
                    break
                
                processed_line = await self.process_line_robust(line, i)
                processed_lines.append(processed_line)
                
                if i % 100 == 0 and i > 0:
                    await asyncio.sleep(0)
                
                if i % 1000 == 0 and i > 0:
                    self.logger.debug(f"Progress [seq={self.sequence_num}]: {i}/{len(input_lines)} lines")
            
            # Generate clean output
            processing_time = time.time() - self.start_time
            input_hash = hashlib.md5('\n'.join(input_lines).encode('utf-8', errors='replace')).hexdigest()[:8]
            
            if self.file_writer and self.sequence_num is not None:
                # Create CLEAN content - only processed lines, NO metadata
                content = '\n'.join(processed_lines) + '\n'
                metadata = f"instance={self.instance_id}, {len(processed_lines)} lines, hash={input_hash}"
                
                await self.file_writer.queue_for_writing(self.sequence_num, content, metadata)
                await self.file_writer.finalize_remaining(timeout=120.0)
                
            else:
                # Write to stdout - clean content only
                for line in processed_lines:
                    print(line, flush=True)
            
            final_time = time.time() - self.start_time
            self.logger.info(f"Completed [seq={self.sequence_num}, instance={self.instance_id}]: "
                           f"{len(input_lines)} -> {len(processed_lines)} lines in {final_time:.2f}s")
            
        except Exception as e:
            self.logger.error(f"Critical error in processing [seq={self.sequence_num}, instance={self.instance_id}]: {e}")
            raise

class RobustFileProcessor:
    """Robust file processor with clean output and temp files only."""
    
    def __init__(self, integrator, input_file: Path, output_file: Optional[Path] = None):
        self.integrator = integrator
        self.input_file = input_file
        self.output_file = output_file
        self.logger = logging.getLogger(__name__)
        
        self.instance_id = f"file_{uuid.uuid4().hex[:8]}"
        self.start_time = time.time()
        self.processing_cancelled = False
        
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating graceful shutdown")
            self.processing_cancelled = True
        
        try:
            # SIGINT (Ctrl+C) is available on both Unix and Windows
            signal.signal(signal.SIGINT, signal_handler)
            
            # SIGTERM is Unix-only, only set if available
            if hasattr(signal, 'SIGTERM'):
                signal.signal(signal.SIGTERM, signal_handler)
            
            # Windows-specific signals
            if platform.system() == 'Windows':
                if hasattr(signal, 'SIGBREAK'):
                    signal.signal(signal.SIGBREAK, signal_handler)
        except Exception as e:
            self.logger.warning(f"Could not setup signal handlers: {e}")
    
    def read_input_file_robust(self) -> List[str]:
        """Read input file with robust error handling."""
        try:
            if not self.input_file.exists():
                self.logger.error(f"Input file does not exist: {self.input_file}")
                return []
            
            if not self.input_file.is_file():
                self.logger.error(f"Input path is not a file: {self.input_file}")
                return []
            
            file_size = self.input_file.stat().st_size
            if file_size > 100 * 1024 * 1024:
                self.logger.warning(f"Large file detected: {file_size / (1024*1024):.1f}MB")
            
            lines = []
            line_count = 0
            
            with open(self.input_file, 'r', encoding='utf-8', errors='replace') as f:
                for line_num, line in enumerate(f, 1):
                    if self.processing_cancelled:
                        self.logger.info(f"Reading cancelled at line {line_num}")
                        break
                    
                    line = line.rstrip('\r\n')
                    lines.append(line)
                    line_count += 1
                    
                    if line_count > 1000000:
                        self.logger.error(f"Too many lines: {line_count}, stopping")
                        break
                    
                    if len(line) > 100000:
                        self.logger.warning(f"Very long line ({len(line)} chars) on line {line_num}")
                    
                    if line_count % 10000 == 0:
                        self.logger.debug(f"Read {line_count} lines")
            
            input_hash = hashlib.md5('\n'.join(lines).encode('utf-8', errors='replace')).hexdigest()[:8]
            
            self.logger.info(f"Read file {self.input_file}: {len(lines)} lines, hash={input_hash}")
            return lines
            
        except Exception as e:
            self.logger.error(f"Error reading {self.input_file}: {e}")
            return []
    
    def process_line_robust(self, line: str, line_index: int) -> str:
        """Process single line with error recovery."""
        try:
            if not line.strip():
                return line
            
            if self.processing_cancelled:
                return line
            
            analyzer_results = self.integrator.analyze_text(line)
            
            self.integrator.stats.lines_processed += 1
            
            if analyzer_results:
                self.integrator.stats.lines_with_findings += 1
                self.integrator.stats.entities_found += len(analyzer_results)
                
                secrets_count = sum(1 for r in analyzer_results if r.entity_type.startswith('SECRET_'))
                self.integrator.stats.secrets_found += secrets_count
                
                processed_line = self.integrator.pseudonymize_text(line, analyzer_results)
                return processed_line
            else:
                return line
                
        except Exception as e:
            self.logger.error(f"Error processing line {line_index + 1}: {e}")
            self.integrator.stats.errors += 1
            return line
    
    def write_output_file_robust(self, processed_lines: List[str]) -> bool:
        """Write clean output file - use temp file for atomic writes."""
        try:
            if not self.output_file:
                # Write to stdout - clean content only
                for line in processed_lines:
                    print(line)
                return True
            
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Use temp directory for atomic writes
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, 
                                           dir=self.output_file.parent, 
                                           prefix=f"{self.output_file.name}.tmp.") as temp_file:
                
                temp_path = Path(temp_file.name)
                
                try:
                    # Write ONLY the processed content - NO metadata headers
                    for line in processed_lines:
                        temp_file.write(line + '\n')
                    
                    temp_file.flush()
                    if hasattr(os, 'fsync'):
                        os.fsync(temp_file.fileno())
                    
                    # Atomic move (works on both Unix and Windows)
                    temp_path.replace(self.output_file)
                    self.logger.info(f"Successfully wrote {len(processed_lines)} lines to {self.output_file}")
                    return True
                    
                except Exception as e:
                    # Cleanup temp file on error
                    try:
                        temp_path.unlink()
                    except:
                        pass
                    raise e
                
        except Exception as e:
            self.logger.error(f"Error writing output file: {e}")
            return False
    
    def process_file_robust(self) -> Dict[str, Any]:
        """Main file processing with comprehensive error handling."""
        self.logger.info(f"Starting file processing: {self.input_file} -> {self.output_file or 'stdout'}")
        
        results = {
            "input_file": str(self.input_file),
            "output_file": str(self.output_file) if self.output_file else "stdout",
            "success": False,
            "stats": {},
            "entity_mapping": {},
            "errors": []
        }
        
        try:
            input_lines = self.read_input_file_robust()
            
            if self.processing_cancelled:
                self.logger.info("Processing cancelled during file reading")
                results["errors"].append("Processing cancelled during file reading")
                return results
            
            if not input_lines:
                self.logger.warning(f"No content read from {self.input_file}")
                results["errors"].append("No content read from input file")
                
                if self.output_file:
                    self.write_output_file_robust([])
                results["success"] = True
                return results
            
            processed_lines = []
            
            for i, line in enumerate(input_lines):
                if self.processing_cancelled:
                    self.logger.warning(f"Processing cancelled at line {i+1}/{len(input_lines)}")
                    results["errors"].append(f"Processing cancelled at line {i+1}")
                    break
                
                processed_line = self.process_line_robust(line, i)
                processed_lines.append(processed_line)
                
                if i > 0 and (i + 1) % 1000 == 0:
                    self.logger.debug(f"Progress: {i+1}/{len(input_lines)} lines")
            
            write_success = self.write_output_file_robust(processed_lines)
            if not write_success:
                results["errors"].append("Failed to write output file")
                return results
            
            results["success"] = True
            results["stats"] = asdict(self.integrator.stats)
            results["entity_mapping"] = self.integrator.entity_mapping
            
            final_time = time.time() - self.start_time
            self.logger.info(f"File processing complete: {len(input_lines)} -> {len(processed_lines)} lines in {final_time:.2f}s")
            
            if not self.integrator.quiet:
                print(f"Processing complete:", file=sys.stderr)
                print(f"  Input file: {self.input_file}", file=sys.stderr)
                print(f"  Lines processed: {self.integrator.stats.lines_processed}", file=sys.stderr)
                print(f"  Lines with findings: {self.integrator.stats.lines_with_findings}", file=sys.stderr)
                print(f"  Entities found: {self.integrator.stats.entities_found}", file=sys.stderr)
                print(f"  Secrets found: {self.integrator.stats.secrets_found}", file=sys.stderr)
                print(f"  Errors: {self.integrator.stats.errors}", file=sys.stderr)
                print(f"  Processing time: {final_time:.2f}s", file=sys.stderr)
            
            return results
            
        except Exception as e:
            error_msg = f"Critical error in file processing: {e}"
            self.logger.error(error_msg)
            results["errors"].append(error_msg)
            return results

# [Rest of classes remain the same - keeping for brevity]
class StructuredFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'level': record.levelname,
            'message': record.getMessage(),
            'pid': os.getpid()
        }
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

def setup_logging(log_level: str = 'INFO', log_file: Optional[str] = None, quiet: bool = False) -> logging.Logger:
    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, log_level.upper()))
    logger.handlers = []
    
    if not quiet:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s [%(process)d] - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    if log_file:
        try:
            log_file_path = Path(log_file)
            log_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(StructuredFormatter())
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not setup log file {log_file}: {e}")
    
    return logger

class SecretsPatternDownloader:
    REPO_URL = "https://github.com/mazen160/secrets-patterns-db"
    RAW_BASE_URL = "https://raw.githubusercontent.com/mazen160/secrets-patterns-db/master"
    
    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path(tempfile.gettempdir()) / "secrets-patterns-cache"
        self.cache_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)
    
    def download_patterns(self, force_refresh: bool = False) -> Dict[str, Any]:
        patterns_file = self.cache_dir / "patterns.yaml"
        
        if patterns_file.exists() and not force_refresh:
            try:
                with open(patterns_file, 'r', encoding='utf-8') as f:
                    patterns = yaml.safe_load(f)
                    if patterns and isinstance(patterns, dict):
                        self.logger.info(f"Using cached patterns file: {len(patterns.get('patterns', []))} patterns")
                        return patterns
            except Exception as e:
                self.logger.warning(f"Error loading cached patterns: {e}, downloading fresh")
        
        self.logger.info("Downloading patterns from secrets-patterns-db...")
        
        pattern_files = [
            "db/rules-stable.yml",
            "datasets/git-leaks.yml"
            # "datasets/high-confidence.yml" #  "datasets/generic.yml"
        ]
        
        all_patterns = {"patterns": []}
        
        for pattern_file in pattern_files:
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    url = f"{self.RAW_BASE_URL}/{pattern_file}"
                    response = requests.get(url, timeout=60)
                    response.raise_for_status()
                    
                    file_patterns = yaml.safe_load(response.text)
                    if isinstance(file_patterns, dict) and "patterns" in file_patterns:
                        all_patterns["patterns"].extend(file_patterns["patterns"])
                        self.logger.info(f"Downloaded {len(file_patterns['patterns'])} patterns from {pattern_file}")
                    break
                        
                except Exception as e:
                    if attempt < max_retries - 1:
                        self.logger.warning(f"Failed to download {pattern_file} (attempt {attempt + 1}): {e}, retrying...")
                        time.sleep(2 ** attempt)
                    else:
                        self.logger.warning(f"Failed to download {pattern_file} after {max_retries} attempts: {e}")
        
        if all_patterns["patterns"]:
            try:
                with open(patterns_file, 'w', encoding='utf-8') as f:
                    yaml.safe_dump(all_patterns, f)
                self.logger.info(f"Cached {len(all_patterns['patterns'])} total patterns")
            except Exception as e:
                self.logger.warning(f"Could not cache patterns: {e}")
        
        return all_patterns

class ReversiblePseudonymizer(Operator):
    def operate(self, text: str, params: Dict = None) -> str:
        if not text or not isinstance(text, str):
            return text
        
        entity_type = params.get("entity_type", "UNKNOWN") if params else "UNKNOWN"
        entity_mapping = params.get("entity_mapping", {}) if params else {}
        
        if entity_type not in entity_mapping:
            entity_mapping[entity_type] = {}
        
        type_mapping = entity_mapping[entity_type]
        
        if text in type_mapping:
            return type_mapping[text]
        
        index = len(type_mapping)
        pseudonym = f"<{entity_type}_{index}>"
        type_mapping[text] = pseudonym
        
        return pseudonym
    
    def validate(self, params: Dict = None) -> None:
        pass
    
    def operator_name(self) -> str:
        return "reversible_pseudonymize"
    
    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize

class PresidioSecretsIntegrator:
    def __init__(self, cache_dir: Optional[Path] = None, quiet: bool = False):
        self.logger = logging.getLogger(__name__)
        self.quiet = quiet
        self.downloader = SecretsPatternDownloader(cache_dir)
        self.entity_mapping: Dict[str, Dict[str, str]] = {}
        self.stats = ProcessingStats()
        
        try:
            self.registry = RecognizerRegistry()
            self.registry.load_predefined_recognizers()
            
            self.anonymizer = AnonymizerEngine()
            self.anonymizer.add_anonymizer(ReversiblePseudonymizer)
            
            self.analyzer = None
            self._pattern_cache: Dict[str, re.Pattern] = {}
            
            self.logger.info("Initialized Presidio components successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Presidio: {e}")
            raise
    
    def confidence_score_from_level(self, confidence_level: str) -> float:
        mapping = {"high": 0.8, "medium": 0.6, "low": 0.3}
        return mapping.get(str(confidence_level).lower(), 0.5)
    
    def create_pattern_recognizer(self, pattern_data: Dict) -> Optional[PatternRecognizer]:
        try:
            if not isinstance(pattern_data, dict):
                return None
                
            name = pattern_data.get("name", "Unknown")
            regex = pattern_data.get("regex", "")
            confidence = pattern_data.get("confidence", "medium")
            
            if not regex or not isinstance(regex, str):
                return None
            
            if regex not in self._pattern_cache:
                try:
                    compiled_regex = re.compile(regex)
                    compiled_regex.search("test")
                    self._pattern_cache[regex] = compiled_regex
                except (re.error, TypeError, ValueError):
                    return None
            
            pattern = Pattern(
                name=f"{name}_pattern",
                regex=regex,
                score=self.confidence_score_from_level(confidence)
            )
            
            safe_name = re.sub(r'[^A-Z0-9_]', '_', str(name).upper())
            entity_name = f"SECRET_{safe_name}"
            
            recognizer = PatternRecognizer(
                supported_entity=entity_name,
                patterns=[pattern],
                context=[str(name).lower(), "secret", "key", "token", "api"],
                supported_language="en",
                name=f"{safe_name}_recognizer"
            )
            
            return recognizer
            
        except Exception:
            return None
    
    def load_secrets_patterns(self, force_refresh: bool = False) -> int:
        try:
            self.logger.info("Loading secrets patterns...")
            
            patterns_data = self.downloader.download_patterns(force_refresh)
            if not patterns_data or not isinstance(patterns_data, dict):
                patterns_data = {"patterns": []}
            
            added_count = 0
            error_count = 0
            
            for pattern_data in patterns_data.get("patterns", []):
                try:
                    if not isinstance(pattern_data, dict) or "pattern" not in pattern_data:
                        continue
                    
                    pattern_info = pattern_data["pattern"]
                    recognizer = self.create_pattern_recognizer(pattern_info)
                    
                    if recognizer:
                        self.registry.add_recognizer(recognizer)
                        added_count += 1
                    else:
                        error_count += 1
                        
                except Exception:
                    error_count += 1
            
            try:
                self.analyzer = AnalyzerEngine(registry=self.registry)
                self.logger.info(f"Successfully loaded {added_count} secret patterns ({error_count} errors)")
            except Exception as e:
                self.logger.error(f"Failed to create analyzer: {e}")
                raise
                
            return added_count
            
        except Exception as e:
            self.logger.error(f"Critical error loading patterns: {e}")
            raise
    
    def analyze_text(self, text: str, language: str = "en") -> List[RecognizerResult]:
        if not self.analyzer or not text or not isinstance(text, str):
            return []
        
        try:
            results = self.analyzer.analyze(
                text=text,
                language=language,
                score_threshold=0.1
            )
            return results or []
        except Exception:
            return []
    
    def pseudonymize_text(self, text: str, analyzer_results: List[RecognizerResult]) -> str:
        if not analyzer_results or not text:
            return text
        
        try:
            operators = {}
            for result in analyzer_results:
                if hasattr(result, 'entity_type') and result.entity_type:
                    operators[result.entity_type] = OperatorConfig(
                        "reversible_pseudonymize",
                        {
                            "entity_type": result.entity_type,
                            "entity_mapping": self.entity_mapping
                        }
                    )
            
            if not operators:
                return text
            
            anonymized_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=operators
            )
            
            return anonymized_result.text if anonymized_result else text
            
        except Exception:
            return text
    
    def process_files(self, input_files: List[Path], output_file: Optional[Path] = None) -> List[Dict[str, Any]]:
        """Process multiple input files."""
        if len(input_files) == 1 and output_file:
            processor = RobustFileProcessor(self, input_files[0], output_file)
            result = processor.process_file_robust()
            return [result]
        
        elif len(input_files) == 1 and not output_file:
            processor = RobustFileProcessor(self, input_files[0], None)
            result = processor.process_file_robust()
            return [result]
        
        else:
            results = []
            for input_file in input_files:
                if output_file:
                    output_name = f"{input_file.stem}_redacted{input_file.suffix}"
                    file_output = output_file.parent / output_name if output_file.parent != Path('.') else Path(output_name)
                else:
                    file_output = None
                
                processor = RobustFileProcessor(self, input_file, file_output)
                result = processor.process_file_robust()
                results.append(result)
            
            return results
    
    async def process_stdin_async(self, output_file: Optional[Path] = None):
        """Process stdin with robust sequence management."""
        sequence_num = None
        
        try:
            # Reserve sequence number BEFORE processing ONLY if output file specified
            if output_file:
                sequence_manager = RobustSequenceManager(output_file)
                sequence_num = sequence_manager.get_next_sequence()
                self.logger.info(f"Reserved sequence number: {sequence_num}")
            
            processor = RobustAsyncLineProcessor(self, output_file, sequence_num)
            await processor.process_stdin_stream_robust()
            
        except Exception as e:
            self.logger.error(f"Error in stdin processing (seq={sequence_num}): {e}")
            raise
    
    def save_mapping_table(self, mapping_file: Path):
        """Save mapping table using temp files for atomic writes."""
        try:
            mapping_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Use temp file for atomic write
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, 
                                           dir=mapping_file.parent, 
                                           prefix=f"{mapping_file.name}.tmp.") as temp_file:
                temp_path = Path(temp_file.name)
                
                try:
                    json.dump(self.entity_mapping, temp_file, indent=2, ensure_ascii=False)
                    temp_file.flush()
                    if hasattr(os, 'fsync'):
                        os.fsync(temp_file.fileno())
                    
                    # Atomic move (works on both Unix and Windows)
                    temp_path.replace(mapping_file)
                    self.logger.info(f"Mapping table saved to: {mapping_file}")
                    
                except Exception as e:
                    try:
                        temp_path.unlink()
                    except:
                        pass
                    raise e
            
        except Exception as e:
            self.logger.error(f"Error saving mapping table: {e}")
            raise

class RobustFileWatcher:
    """Cross-platform file watcher for continuous sanitization."""
    
    def __init__(self, integrator, watch_file: Path, output_file: Path):
        self.integrator = integrator
        self.watch_file = watch_file
        self.watch_dir = watch_file.parent
        self.output_file = output_file
        self.logger = logging.getLogger(__name__)
        self.observer = None
        self.processing_lock = threading.Lock()
        self.shutdown_event = threading.Event()
        
        if not HAS_WATCHDOG:
            raise RuntimeError("Watchdog library not available. Install with: pip install watchdog")
        
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, stopping file watcher")
            self.stop_watching()
        
        try:
            signal.signal(signal.SIGINT, signal_handler)
            if hasattr(signal, 'SIGTERM'):
                signal.signal(signal.SIGTERM, signal_handler)
            if platform.system() == 'Windows' and hasattr(signal, 'SIGBREAK'):
                signal.signal(signal.SIGBREAK, signal_handler)
        except Exception as e:
            self.logger.warning(f"Could not setup signal handlers: {e}")
    
    def _process_file_safely(self, file_path: Path):
        """Process a file with robust error handling."""
        try:
            # Only process the specific file we're watching
            if file_path != self.watch_file:
                return
                
            if not file_path.exists() or not file_path.is_file():
                return
            
            with self.processing_lock:
                if self.shutdown_event.is_set():
                    return
                
                self.logger.info(f"Processing watched file: {file_path}")
                
                # Use the existing file processor
                processor = RobustFileProcessor(self.integrator, file_path, None)
                lines = processor.read_input_file_robust()
                
                if not lines:
                    return
                
                # Process lines
                processed_lines = []
                for i, line in enumerate(lines):
                    if self.shutdown_event.is_set():
                        break
                    processed_line = processor.process_line_robust(line, i)
                    processed_lines.append(processed_line)
                
                # Write complete processed content to output file (no metadata)
                if processed_lines and not self.shutdown_event.is_set():
                    self._write_to_output(processed_lines)
                
        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {e}")
    
    def _write_to_output(self, processed_lines: List[str]):
        """Write processed lines to output file, replacing previous content."""
        try:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Use temp file for atomic write
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', delete=False, 
                                           dir=self.output_file.parent, 
                                           prefix=f"{self.output_file.name}.tmp.") as temp_file:
                temp_path = Path(temp_file.name)
                
                try:
                    # Write ONLY the processed content - NO metadata
                    for line in processed_lines:
                        temp_file.write(line + '\n')
                    
                    temp_file.flush()
                    if hasattr(os, 'fsync'):
                        os.fsync(temp_file.fileno())
                    
                    # Atomic move (works on both Unix and Windows)
                    temp_path.replace(self.output_file)
                    
                    self.logger.info(f"Updated output file with {len(processed_lines)} processed lines")
                    
                except Exception as e:
                    # Cleanup temp file on error
                    try:
                        temp_path.unlink()
                    except:
                        pass
                    raise e
            
        except Exception as e:
            self.logger.error(f"Error writing to output file: {e}")
    
    def start_watching(self):
        """Start watching the file for changes."""
        if not self.watch_file.exists():
            raise FileNotFoundError(f"Watch file does not exist: {self.watch_file}")
        
        if not self.watch_file.is_file():
            raise ValueError(f"Watch path is not a file: {self.watch_file}")
        
        class FileEventHandler(FileSystemEventHandler):
            def __init__(self, watcher):
                self.watcher = watcher
                super().__init__()
            
            def on_created(self, event):
                if not event.is_directory:
                    file_path = Path(event.src_path)
                    self.watcher.logger.debug(f"File created: {file_path}")
                    # Small delay to ensure file is fully written
                    threading.Timer(0.5, self.watcher._process_file_safely, args=[file_path]).start()
            
            def on_modified(self, event):
                if not event.is_directory:
                    file_path = Path(event.src_path)
                    self.watcher.logger.debug(f"File modified: {file_path}")
                    # Small delay to ensure file is fully written
                    threading.Timer(0.5, self.watcher._process_file_safely, args=[file_path]).start()
        
        try:
            self.observer = Observer()
            event_handler = FileEventHandler(self)
            self.observer.schedule(event_handler, str(self.watch_dir), recursive=False)
            
            self.observer.start()
            self.logger.info(f"Started watching file: {self.watch_file}")
            self.logger.info(f"Output will be written to: {self.output_file}")
            
            # Process the file initially
            self._process_file_safely(self.watch_file)
            
            # Keep the main thread alive
            try:
                while not self.shutdown_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Keyboard interrupt received")
            
        except Exception as e:
            self.logger.error(f"Error starting file watcher: {e}")
            raise
        finally:
            self.stop_watching()
    
    def stop_watching(self):
        """Stop the file watcher."""
        self.shutdown_event.set()
        
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join(timeout=5.0)
            self.logger.info("File watcher stopped")
        
        # Process the watched file one final time if recently modified
        try:
            if self.watch_file.exists():
                # Check if file was recently modified (within last 10 seconds)
                if time.time() - self.watch_file.stat().st_mtime < 10:
                    self._process_file_safely(self.watch_file)
        except Exception as e:
            self.logger.warning(f"Error in final file processing: {e}")

def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='presidio-secrets-pseudonymizer',
        description='Robust pseudonymization tool with file and stdin processing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single file processing (mapping file allowed)
  %(prog)s input.txt -o output.txt --mapping-file mappings.json
  
  # Multiple files
  %(prog)s file1.txt file2.txt -o output_dir/
  
  # File to stdout
  %(prog)s input.txt
  
  # Stdin processing (NO mapping file allowed)
  cat input.txt | %(prog)s --stdin -o output.txt
  
  # Watchdog mode (NO mapping file allowed)
  %(prog)s --watchdog /path/to/file.txt -o output.txt
        """
    )
    
    parser.add_argument('input_files', nargs='*', type=Path, help='Input files to process')
    parser.add_argument('--stdin', action='store_true', help='Process stdin input')
    parser.add_argument('-o', '--output', type=Path, help='Output file or directory')
    parser.add_argument('--mapping-file', type=Path, help='Entity mappings file (file mode only)')
    parser.add_argument('--watchdog', type=Path, help='Watch a specific file for changes and sanitize continuously')
    parser.add_argument('--refresh-patterns', action='store_true', help='Force refresh of pattern cache')
    parser.add_argument('--cache-dir', type=Path, help='Pattern cache directory')
    parser.add_argument('--quiet', action='store_true', help='Suppress progress output')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO')
    parser.add_argument('--debug-log', type=Path, help='Debug log file')
    
    return parser

async def main_async():
    """Main async entry point with corrected behavior."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    logger = setup_logging(
        args.log_level, 
        str(args.debug_log) if args.debug_log else None, 
        args.quiet
    )
    
    try:
        logger.info("Starting robust pseudonymization tool")
        
        # Validate arguments
        mode_count = sum([bool(args.stdin), bool(args.watchdog), bool(args.input_files)])
        if mode_count != 1:
            logger.error("Must specify exactly one mode: input files, --stdin, or --watchdog")
            sys.exit(1)
        
        if args.stdin:
            if args.mapping_file:
                logger.error("Mapping file not allowed with --stdin mode")
                sys.exit(1)
        elif args.watchdog:
            if not args.output:
                logger.error("Output file (-o) required with --watchdog mode")
                sys.exit(1)
            if args.mapping_file:
                logger.error("Mapping file not allowed with --watchdog mode")
                sys.exit(1)
            if not args.watchdog.exists():
                logger.error(f"Watch file does not exist: {args.watchdog}")
                sys.exit(1)
            if not args.watchdog.is_file():
                logger.error(f"Watch path is not a file: {args.watchdog}")
                sys.exit(1)
        else:
            for input_file in args.input_files:
                if not input_file.exists():
                    logger.error(f"Input file does not exist: {input_file}")
                    sys.exit(1)
        
        # Initialize integrator
        integrator = PresidioSecretsIntegrator(args.cache_dir, args.quiet)
        pattern_count = integrator.load_secrets_patterns(args.refresh_patterns)
        
        if pattern_count == 0:
            logger.warning("No patterns loaded, continuing with built-in recognizers only")
        
        if args.stdin:
            await integrator.process_stdin_async(args.output)
        elif args.watchdog:
            # Watchdog mode
            watcher = RobustFileWatcher(integrator, args.watchdog, args.output)
            watcher.start_watching()
        else:
            # File mode
            results = integrator.process_files(args.input_files, args.output)
            
            failed_files = [r for r in results if not r.get("success", False)]
            if failed_files:
                logger.error(f"Failed to process {len(failed_files)} files")
                for result in failed_files:
                    logger.error(f"  {result['input_file']}: {result.get('errors', ['Unknown error'])}")
                sys.exit(1)
            
            # Save mapping file ONLY in file mode
            if args.mapping_file:
                integrator.save_mapping_table(args.mapping_file)
        
    except KeyboardInterrupt:
        logger.info("Processing interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Critical error: {e}")
        logger.debug("Full traceback:", exc_info=True)
        sys.exit(1)

def main():
    """Main entry point with exception handling."""
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()