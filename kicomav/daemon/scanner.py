# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Daemon Scanner Module

This module provides a shared scan engine wrapper for the daemon:
- Singleton engine management
- Thread-safe scanning operations
- Statistics tracking
- Stream scanning support
"""

import datetime
import hashlib
import logging
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from .config import get_daemon_config

logger = logging.getLogger(__name__)


class ScanStatus(str, Enum):
    """Scan result status."""

    CLEAN = "clean"
    INFECTED = "infected"
    ERROR = "error"


@dataclass
class ScanResult:
    """Result of a file scan."""

    filename: str
    status: ScanStatus
    malware_name: Optional[str] = None
    scan_time_ms: int = 0
    error_message: Optional[str] = None
    sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "filename": self.filename,
            "status": self.status.value,
            "scan_time_ms": self.scan_time_ms,
        }
        if self.malware_name:
            result["malware"] = self.malware_name
        if self.error_message:
            result["error"] = self.error_message
        if self.sha256:
            result["sha256"] = self.sha256
        return result


@dataclass
class VersionInfo:
    """Engine version information."""

    version: str
    build_date: str
    signatures: int
    last_update: datetime.datetime
    engine_count: int

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "version": self.version,
            "build_date": self.build_date,
            "signatures": self.signatures,
            "last_update": self.last_update.isoformat(),
            "engine_count": self.engine_count,
        }


@dataclass
class Stats:
    """Daemon statistics."""

    start_time: datetime.datetime = field(default_factory=datetime.datetime.now)
    scans_total: int = 0
    files_scanned: int = 0
    malware_found: int = 0
    errors: int = 0
    total_scan_time_ms: int = 0

    @property
    def uptime_seconds(self) -> int:
        """Get uptime in seconds."""
        delta = datetime.datetime.now() - self.start_time
        return int(delta.total_seconds())

    @property
    def avg_scan_time_ms(self) -> float:
        """Get average scan time in milliseconds."""
        if self.files_scanned == 0:
            return 0.0
        return self.total_scan_time_ms / self.files_scanned

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "uptime_seconds": self.uptime_seconds,
            "scans_total": self.scans_total,
            "files_scanned": self.files_scanned,
            "malware_found": self.malware_found,
            "errors": self.errors,
            "avg_scan_time_ms": round(self.avg_scan_time_ms, 2),
        }

    def record_scan(self, result: ScanResult) -> None:
        """Record a scan result in statistics."""
        self.files_scanned += 1
        self.total_scan_time_ms += result.scan_time_ms
        if result.status == ScanStatus.INFECTED:
            self.malware_found += 1
        elif result.status == ScanStatus.ERROR:
            self.errors += 1


class DaemonScanner:
    """Shared scan engine wrapper for daemon mode.

    This class manages the antivirus engine lifecycle and provides
    thread-safe scanning operations.
    """

    _instance: Optional["DaemonScanner"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "DaemonScanner":
        """Singleton pattern implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the scanner."""
        if self._initialized:
            return

        self._engine = None
        self._kav_instance = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self._stats = Stats()
        self._scan_lock = threading.Lock()
        self._initialized = True
        self._running = False

    def initialize(self) -> bool:
        """Initialize the scan engine.

        Returns:
            True if initialization successful
        """
        if self._running:
            return True

        try:
            from kicomav import __version__ as KICOMAV_VERSION
            from kicomav import __last_update__ as KICOMAV_BUILDDATE
            from kicomav.kavcore import k2engine

            logger.info("Initializing KicomAV daemon scanner...")

            # Get plugins path
            k2_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            plugins_path = os.path.join(k2_dir, "plugins")

            # Create engine
            self._engine = k2engine.Engine()

            # Set plugins
            if not self._engine.set_plugins(plugins_path):
                logger.error("Failed to load plugins from %s", plugins_path)
                return False

            # Create instance
            self._kav_instance = self._engine.create_instance()
            if not self._kav_instance:
                logger.error("Failed to create engine instance")
                return False

            # Initialize the instance
            if not self._kav_instance.init():
                logger.error("Failed to initialize engine instance")
                return False

            # Store version info
            self._version = KICOMAV_VERSION
            self._build_date = KICOMAV_BUILDDATE

            # Initialize thread pool
            config = get_daemon_config()
            self._executor = ThreadPoolExecutor(max_workers=config.max_workers)

            self._running = True
            logger.info("KicomAV daemon scanner initialized successfully")
            logger.info("  Version: %s", self._version)
            logger.info("  Signatures: %s", format(self._kav_instance.get_signum(), ","))

            return True

        except Exception as e:
            logger.exception("Failed to initialize scanner: %s", e)
            return False

    def shutdown(self) -> None:
        """Shutdown the scan engine."""
        if not self._running:
            return

        logger.info("Shutting down KicomAV daemon scanner...")

        self._running = False

        # Shutdown thread pool
        if self._executor:
            self._executor.shutdown(wait=True)
            self._executor = None

        # Uninitialize engine instance
        if self._kav_instance:
            self._kav_instance.uninit()
            self._kav_instance = None

        # Cleanup engine
        if self._engine:
            self._engine = None

        logger.info("KicomAV daemon scanner shutdown complete")

    def is_running(self) -> bool:
        """Check if scanner is running."""
        return self._running

    def get_version(self) -> VersionInfo:
        """Get engine version information."""
        if not self._running or not self._kav_instance:
            return VersionInfo(
                version="unknown",
                build_date="unknown",
                signatures=0,
                last_update=datetime.datetime.now(),
                engine_count=0,
            )

        return VersionInfo(
            version=self._version,
            build_date=self._build_date,
            signatures=self._kav_instance.get_signum(),
            last_update=self._engine.max_datetime if self._engine else datetime.datetime.now(),
            engine_count=len(self._kav_instance.kavmain_inst) if self._kav_instance else 0,
        )

    def get_stats(self) -> Stats:
        """Get daemon statistics."""
        return self._stats

    def reload_signatures(self) -> bool:
        """Reload signature databases.

        Returns:
            True if reload successful
        """
        if not self._running:
            return False

        logger.info("Reloading signatures...")

        # For now, we reinitialize the entire engine
        # A more sophisticated implementation could do a hot reload
        with self._scan_lock:
            self.shutdown()
            result = self.initialize()

        if result:
            logger.info("Signatures reloaded successfully")
        else:
            logger.error("Failed to reload signatures")

        return result

    def _calculate_sha256(self, filepath: str) -> Optional[str]:
        """Calculate SHA256 hash of a file."""
        try:
            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception:
            return None

    def scan_file(self, filepath: str, include_hash: bool = False) -> ScanResult:
        """Scan a single file.

        Args:
            filepath: Path to the file to scan
            include_hash: Include SHA256 hash in result

        Returns:
            ScanResult object
        """
        if not self._running:
            return ScanResult(
                filename=filepath,
                status=ScanStatus.ERROR,
                error_message="Scanner not running",
            )

        start_time = time.time()
        result_data = {"malware_name": None, "error": None}

        def scan_callback(ret_value):
            """Callback to capture scan results."""
            from kicomav.plugins import kernel

            if ret_value["result"]:
                if ret_value["scan_state"] in (kernel.INFECTED, kernel.SUSPECT):
                    result_data["malware_name"] = ret_value["virus_name"]
            return 0  # K2_ACTION_IGNORE

        try:
            with self._scan_lock:
                self._kav_instance.set_result()
                self._kav_instance.scan(
                    filepath,
                    scan_callback,
                    lambda *args: None,  # disinfect callback
                    lambda *args: None,  # update callback
                    lambda *args: None,  # quarantine callback
                )
                scan_result = self._kav_instance.get_result()

            elapsed_ms = int((time.time() - start_time) * 1000)

            if result_data["malware_name"]:
                status = ScanStatus.INFECTED
            else:
                status = ScanStatus.CLEAN

            result = ScanResult(
                filename=os.path.basename(filepath),
                status=status,
                malware_name=result_data["malware_name"],
                scan_time_ms=elapsed_ms,
                sha256=self._calculate_sha256(filepath) if include_hash else None,
            )

        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            result = ScanResult(
                filename=os.path.basename(filepath),
                status=ScanStatus.ERROR,
                error_message=str(e),
                scan_time_ms=elapsed_ms,
            )

        # Update statistics
        self._stats.record_scan(result)
        self._stats.scans_total += 1

        return result

    def scan_stream(self, data: bytes, filename: str = "stream") -> ScanResult:
        """Scan data from a stream.

        Args:
            data: Byte data to scan
            filename: Optional filename for the stream

        Returns:
            ScanResult object
        """
        if not self._running:
            return ScanResult(
                filename=filename,
                status=ScanStatus.ERROR,
                error_message="Scanner not running",
            )

        # Write data to a temporary file
        try:
            with tempfile.NamedTemporaryFile(delete=False, prefix="k2d_scan_") as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            # Scan the temporary file
            result = self.scan_file(tmp_path)
            result.filename = filename

            # Calculate hash from data directly
            result.sha256 = hashlib.sha256(data).hexdigest()

            return result

        except Exception as e:
            return ScanResult(
                filename=filename,
                status=ScanStatus.ERROR,
                error_message=str(e),
            )
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def scan_directory(
        self,
        dirpath: str,
        recursive: bool = True,
        callback: Optional[Callable[[ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """Scan a directory.

        Args:
            dirpath: Path to directory to scan
            recursive: Scan subdirectories recursively
            callback: Optional callback for each file scanned

        Returns:
            List of ScanResult objects
        """
        results = []

        if not self._running:
            return [
                ScanResult(
                    filename=dirpath,
                    status=ScanStatus.ERROR,
                    error_message="Scanner not running",
                )
            ]

        if not os.path.isdir(dirpath):
            return [
                ScanResult(
                    filename=dirpath,
                    status=ScanStatus.ERROR,
                    error_message="Not a directory",
                )
            ]

        # Collect files to scan
        files_to_scan = []
        if recursive:
            for root, dirs, files in os.walk(dirpath):
                for filename in files:
                    files_to_scan.append(os.path.join(root, filename))
        else:
            for entry in os.scandir(dirpath):
                if entry.is_file():
                    files_to_scan.append(entry.path)

        # Scan each file
        for filepath in files_to_scan:
            result = self.scan_file(filepath)
            results.append(result)
            if callback:
                callback(result)

        return results

    def scan_file_async(self, filepath: str, include_hash: bool = False) -> Future:
        """Scan a file asynchronously.

        Args:
            filepath: Path to the file to scan
            include_hash: Include SHA256 hash in result

        Returns:
            Future object that will contain ScanResult
        """
        if not self._executor:
            raise RuntimeError("Scanner not initialized")
        return self._executor.submit(self.scan_file, filepath, include_hash)


# Convenience function to get the singleton scanner
def get_scanner() -> DaemonScanner:
    """Get the daemon scanner singleton."""
    return DaemonScanner()
