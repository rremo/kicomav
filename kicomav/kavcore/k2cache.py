# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Scan Cache Module

This module provides file hash caching to skip unchanged files during rescans:
- SQLite-based persistent storage
- File modification time and size tracking
- Signature version awareness
- Configurable cache expiration

Usage:
    from kicomav.kavcore.k2cache import ScanCache

    cache = ScanCache()

    # Check if file needs scanning
    if cache.needs_scan("/path/to/file", signature_version="1.0"):
        # Perform scan
        cache.update("/path/to/file", "sha256...", "clean", signature_version="1.0")
    else:
        # Use cached result
        result = cache.get("/path/to/file")
"""

import json
import os
import sqlite3
import stat
import hashlib
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple
from contextlib import contextmanager


class ScanCache:
    """SQLite-based scan result cache."""

    # Default cache location
    DEFAULT_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".kicomav")
    DEFAULT_CACHE_FILE = "cache.db"
    DEFAULT_EXPIRE_DAYS = 7

    def __init__(
        self,
        cache_path: Optional[str] = None,
        expire_days: int = DEFAULT_EXPIRE_DAYS,
    ):
        """Initialize the scan cache.

        Args:
            cache_path: Path to cache database file. If None, uses default location.
            expire_days: Number of days before cache entries expire. 0 = never expire.
        """
        if cache_path is None:
            cache_dir = self.DEFAULT_CACHE_DIR
            os.makedirs(cache_dir, exist_ok=True)
            # Security: Set restrictive permissions on cache directory (0o700)
            try:
                os.chmod(cache_dir, stat.S_IRWXU)  # Owner read/write/execute only
            except (OSError, PermissionError):
                pass  # Ignore on Windows or permission errors
            cache_path = os.path.join(cache_dir, self.DEFAULT_CACHE_FILE)

        self.cache_path = cache_path
        self.expire_days = expire_days
        self._local = threading.local()
        self._init_db()

        # Security: Set restrictive permissions on cache file (0o600)
        try:
            os.chmod(self.cache_path, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only
        except (OSError, PermissionError):
            pass  # Ignore on Windows or permission errors

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "connection") or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                self.cache_path,
                check_same_thread=False,
                timeout=30.0,
            )
            self._local.connection.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrent access
            self._local.connection.execute("PRAGMA journal_mode=WAL")
            self._local.connection.execute("PRAGMA synchronous=NORMAL")
        return self._local.connection

    @contextmanager
    def _get_cursor(self):
        """Get a database cursor with automatic commit/rollback."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

    def _init_db(self) -> None:
        """Initialize the database schema."""
        with self._get_cursor() as cursor:
            # Regular file cache table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_cache (
                    file_path TEXT PRIMARY KEY,
                    file_hash TEXT,
                    file_size INTEGER,
                    file_mtime REAL,
                    scan_date TEXT,
                    scan_result TEXT,
                    malware_name TEXT,
                    signature_version TEXT
                )
            """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scan_date
                ON scan_cache(scan_date)
            """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scan_result
                ON scan_cache(scan_result)
            """
            )

            # Archive file cache table - with composite primary key (archive_path, opt_arc)
            # This allows separate caching for -I and -r -I options
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS archive_cache (
                    archive_path TEXT,
                    archive_hash TEXT,
                    archive_size INTEGER,
                    archive_mtime REAL,
                    contents_hash TEXT,
                    scan_date TEXT,
                    scan_result TEXT,
                    infected_entries TEXT,
                    signature_version TEXT,
                    total_files INTEGER DEFAULT 0,
                    total_packed INTEGER DEFAULT 0,
                    scanned_paths TEXT,
                    opt_arc INTEGER DEFAULT 0,
                    PRIMARY KEY (archive_path, opt_arc)
                )
            """
            )
            # Migration: Check if old table exists with single primary key
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='archive_cache'")
            row = cursor.fetchone()
            if row and "PRIMARY KEY (archive_path, opt_arc)" not in row[0]:
                # Old schema detected, drop and recreate
                cursor.execute("DROP TABLE archive_cache")
                cursor.execute(
                    """
                    CREATE TABLE archive_cache (
                        archive_path TEXT,
                        archive_hash TEXT,
                        archive_size INTEGER,
                        archive_mtime REAL,
                        contents_hash TEXT,
                        scan_date TEXT,
                        scan_result TEXT,
                        infected_entries TEXT,
                        signature_version TEXT,
                        total_files INTEGER DEFAULT 0,
                        total_packed INTEGER DEFAULT 0,
                        scanned_paths TEXT,
                        opt_arc INTEGER DEFAULT 0,
                        PRIMARY KEY (archive_path, opt_arc)
                    )
                """
                )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_archive_scan_date
                ON archive_cache(scan_date)
            """
            )

    def get(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get cached scan result for a file.

        Args:
            file_path: Absolute path to the file

        Returns:
            Dictionary with cache entry or None if not found
        """
        file_path = os.path.abspath(file_path)
        with self._get_cursor() as cursor:
            cursor.execute("SELECT * FROM scan_cache WHERE file_path = ?", (file_path,))
            row = cursor.fetchone()
            if row:
                return dict(row)
        return None

    def update(
        self,
        file_path: str,
        file_hash: str,
        scan_result: str,
        malware_name: Optional[str] = None,
        signature_version: str = "",
    ) -> None:
        """Update or insert cache entry for a file.

        Args:
            file_path: Absolute path to the file
            file_hash: SHA256 hash of the file
            scan_result: Scan result ("clean", "infected", "error")
            malware_name: Name of detected malware (if infected)
            signature_version: Current signature version
        """
        file_path = os.path.abspath(file_path)
        try:
            stat = os.stat(file_path)
            file_size = stat.st_size
            file_mtime = stat.st_mtime
        except OSError:
            return

        scan_date = datetime.now().isoformat()

        with self._get_cursor() as cursor:
            cursor.execute(
                """
                INSERT OR REPLACE INTO scan_cache
                (file_path, file_hash, file_size, file_mtime, scan_date,
                 scan_result, malware_name, signature_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (file_path, file_hash, file_size, file_mtime, scan_date, scan_result, malware_name, signature_version),
            )

    def needs_scan(
        self,
        file_path: str,
        signature_version: str = "",
    ) -> bool:
        """Check if a file needs to be scanned.

        A file needs scanning if:
        - Not in cache
        - File modified (mtime or size changed)
        - Cache entry expired
        - Signature version changed

        Args:
            file_path: Absolute path to the file
            signature_version: Current signature version

        Returns:
            True if file needs scanning, False if cache can be used
        """
        file_path = os.path.abspath(file_path)

        # Get file stats
        try:
            stat = os.stat(file_path)
            current_size = stat.st_size
            current_mtime = stat.st_mtime
        except OSError:
            return True  # Can't stat file, needs scan

        # Get cached entry
        cached = self.get(file_path)
        if cached is None:
            return True  # Not in cache

        # Check if file modified
        if cached["file_size"] != current_size:
            return True
        if abs(cached["file_mtime"] - current_mtime) > 0.001:  # Float comparison
            return True

        # Check signature version
        if signature_version and cached["signature_version"] != signature_version:
            return True

        # Check expiration
        if self.expire_days > 0:
            try:
                scan_date = datetime.fromisoformat(cached["scan_date"])
                expire_date = scan_date + timedelta(days=self.expire_days)
                if datetime.now() > expire_date:
                    return True
            except (ValueError, TypeError):
                return True

        return False

    def get_cached_result(
        self,
        file_path: str,
        signature_version: str = "",
    ) -> Optional[Tuple[str, Optional[str]]]:
        """Get cached scan result if valid.

        Args:
            file_path: Absolute path to the file
            signature_version: Current signature version

        Returns:
            Tuple of (scan_result, malware_name) or None if cache invalid
        """
        if self.needs_scan(file_path, signature_version):
            return None

        cached = self.get(file_path)
        if cached:
            return (cached["scan_result"], cached["malware_name"])
        return None

    def remove(self, file_path: str) -> bool:
        """Remove a file from the cache.

        Args:
            file_path: Absolute path to the file

        Returns:
            True if entry was removed, False if not found
        """
        file_path = os.path.abspath(file_path)
        with self._get_cursor() as cursor:
            cursor.execute("DELETE FROM scan_cache WHERE file_path = ?", (file_path,))
            return cursor.rowcount > 0

    # -------------------------------------------------------------------------
    # Archive Cache Methods
    # -------------------------------------------------------------------------

    def get_archive(self, archive_path: str, opt_arc: bool = False) -> Optional[Dict[str, Any]]:
        """Get cached scan result for an archive.

        Args:
            archive_path: Absolute path to the archive file
            opt_arc: Whether -r option was used (True = full archive scan)

        Returns:
            Dictionary with cache entry or None if not found
        """
        archive_path = os.path.abspath(archive_path)
        with self._get_cursor() as cursor:
            cursor.execute(
                "SELECT * FROM archive_cache WHERE archive_path = ? AND opt_arc = ?",
                (archive_path, 1 if opt_arc else 0),
            )
            row = cursor.fetchone()
            if row:
                result = dict(row)
                # Parse infected_entries JSON
                if result.get("infected_entries"):
                    try:
                        result["infected_entries"] = json.loads(result["infected_entries"])
                    except (json.JSONDecodeError, TypeError):
                        result["infected_entries"] = []
                else:
                    result["infected_entries"] = []
                return result
        return None

    def update_archive(
        self,
        archive_path: str,
        archive_hash: str,
        contents_hash: str,
        scan_result: str,
        infected_entries: Optional[List[Dict[str, str]]] = None,
        signature_version: str = "",
        total_files: int = 0,
        total_packed: int = 0,
        scanned_paths: Optional[List[str]] = None,
        opt_arc: bool = False,
    ) -> None:
        """Update or insert cache entry for an archive.

        Args:
            archive_path: Absolute path to the archive file
            archive_hash: SHA256 hash of the archive file
            contents_hash: Hash of archive contents (internal file list)
            scan_result: Scan result ("clean", "infected")
            infected_entries: List of infected entries [{"path": "...", "malware": "..."}]
            signature_version: Current signature version
            total_files: Total number of files scanned inside this archive (including nested)
            total_packed: Total number of archives inside this archive (including nested)
            scanned_paths: List of all scanned file paths inside this archive (for output replay)
            opt_arc: Whether -r option was used (True = full archive scan)
        """
        archive_path = os.path.abspath(archive_path)
        try:
            stat = os.stat(archive_path)
            archive_size = stat.st_size
            archive_mtime = stat.st_mtime
        except OSError:
            return

        scan_date = datetime.now().isoformat()
        infected_json = json.dumps(infected_entries or [])
        scanned_paths_json = json.dumps(scanned_paths or [])

        with self._get_cursor() as cursor:
            cursor.execute(
                """
                INSERT OR REPLACE INTO archive_cache
                (archive_path, archive_hash, archive_size, archive_mtime, contents_hash,
                 scan_date, scan_result, infected_entries, signature_version, total_files, total_packed, scanned_paths, opt_arc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    archive_path,
                    archive_hash,
                    archive_size,
                    archive_mtime,
                    contents_hash,
                    scan_date,
                    scan_result,
                    infected_json,
                    signature_version,
                    total_files,
                    total_packed,
                    scanned_paths_json,
                    1 if opt_arc else 0,
                ),
            )

    def needs_archive_scan(
        self,
        archive_path: str,
        contents_hash: str,
        signature_version: str = "",
        opt_arc: bool = False,
    ) -> bool:
        """Check if an archive needs to be scanned.

        An archive needs scanning if:
        - Not in cache
        - Archive file modified (mtime or size changed)
        - Archive contents changed (contents_hash differs)
        - Cache entry expired
        - Signature version changed
        - opt_arc option changed (different scan depth)

        Args:
            archive_path: Absolute path to the archive file
            contents_hash: Hash of current archive contents
            signature_version: Current signature version
            opt_arc: Whether -r option is being used (True = full archive scan)

        Returns:
            True if archive needs scanning, False if cache can be used
        """
        archive_path = os.path.abspath(archive_path)

        # Get file stats
        try:
            stat = os.stat(archive_path)
            current_size = stat.st_size
            current_mtime = stat.st_mtime
        except OSError:
            return True  # Can't stat file, needs scan

        # Get cached entry (with matching opt_arc)
        cached = self.get_archive(archive_path, opt_arc)
        if cached is None:
            return True  # Not in cache

        # Check if archive file modified
        if cached["archive_size"] != current_size:
            return True
        if abs(cached["archive_mtime"] - current_mtime) > 0.001:  # Float comparison
            return True

        # Check if contents changed
        if cached["contents_hash"] != contents_hash:
            return True

        # Check signature version
        if signature_version and cached["signature_version"] != signature_version:
            return True

        # Note: opt_arc check is not needed here because get_archive already filters by opt_arc

        # Check expiration
        if self.expire_days > 0:
            try:
                scan_date = datetime.fromisoformat(cached["scan_date"])
                expire_date = scan_date + timedelta(days=self.expire_days)
                if datetime.now() > expire_date:
                    return True
            except (ValueError, TypeError):
                return True

        return False

    def get_archive_cached_result(
        self,
        archive_path: str,
        contents_hash: str,
        signature_version: str = "",
        opt_arc: bool = False,
    ) -> Optional[Tuple[str, List[Dict[str, str]], int, int, List[str]]]:
        """Get cached scan result for an archive if valid.

        Args:
            archive_path: Absolute path to the archive file
            contents_hash: Hash of current archive contents
            signature_version: Current signature version
            opt_arc: Whether -r option is being used (True = full archive scan)

        Returns:
            Tuple of (scan_result, infected_entries, total_files, total_packed, scanned_paths) or None if cache invalid
        """
        if self.needs_archive_scan(archive_path, contents_hash, signature_version, opt_arc):
            return None

        cached = self.get_archive(archive_path, opt_arc)
        if cached:
            # Parse scanned_paths JSON
            scanned_paths = []
            if cached.get("scanned_paths"):
                try:
                    scanned_paths = json.loads(cached["scanned_paths"])
                except (json.JSONDecodeError, TypeError):
                    scanned_paths = []
            return (
                cached["scan_result"],
                cached["infected_entries"],
                cached.get("total_files", 0),
                cached.get("total_packed", 0),
                scanned_paths,
            )
        return None

    def remove_archive(self, archive_path: str) -> bool:
        """Remove an archive from the cache.

        Args:
            archive_path: Absolute path to the archive file

        Returns:
            True if entry was removed, False if not found
        """
        archive_path = os.path.abspath(archive_path)
        with self._get_cursor() as cursor:
            cursor.execute("DELETE FROM archive_cache WHERE archive_path = ?", (archive_path,))
            return cursor.rowcount > 0

    def clear(self) -> int:
        """Clear all cache entries (both file and archive caches).

        Returns:
            Number of entries removed
        """
        with self._get_cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM scan_cache")
            file_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM archive_cache")
            archive_count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM scan_cache")
            cursor.execute("DELETE FROM archive_cache")
            return file_count + archive_count

    def prune_expired(self) -> int:
        """Remove expired cache entries (both file and archive caches).

        Returns:
            Number of entries removed
        """
        if self.expire_days <= 0:
            return 0

        expire_date = datetime.now() - timedelta(days=self.expire_days)
        expire_str = expire_date.isoformat()

        with self._get_cursor() as cursor:
            cursor.execute("DELETE FROM scan_cache WHERE scan_date < ?", (expire_str,))
            file_count = cursor.rowcount
            cursor.execute("DELETE FROM archive_cache WHERE scan_date < ?", (expire_str,))
            archive_count = cursor.rowcount
            return file_count + archive_count

    def prune_missing(self) -> int:
        """Remove cache entries for files that no longer exist (both file and archive caches).

        Returns:
            Number of entries removed
        """
        removed = 0
        with self._get_cursor() as cursor:
            # Prune file cache
            cursor.execute("SELECT file_path FROM scan_cache")
            rows = cursor.fetchall()
            for row in rows:
                file_path = row["file_path"]
                if not os.path.exists(file_path):
                    cursor.execute("DELETE FROM scan_cache WHERE file_path = ?", (file_path,))
                    removed += 1

            # Prune archive cache
            cursor.execute("SELECT archive_path FROM archive_cache")
            rows = cursor.fetchall()
            for row in rows:
                archive_path = row["archive_path"]
                if not os.path.exists(archive_path):
                    cursor.execute("DELETE FROM archive_cache WHERE archive_path = ?", (archive_path,))
                    removed += 1

        return removed

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with self._get_cursor() as cursor:
            # File cache stats
            cursor.execute("SELECT COUNT(*) FROM scan_cache")
            file_total = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT scan_result, COUNT(*) as count
                FROM scan_cache
                GROUP BY scan_result
            """
            )
            file_by_result = {row["scan_result"]: row["count"] for row in cursor.fetchall()}

            # Archive cache stats
            cursor.execute("SELECT COUNT(*) FROM archive_cache")
            archive_total = cursor.fetchone()[0]

            cursor.execute(
                """
                SELECT scan_result, COUNT(*) as count
                FROM archive_cache
                GROUP BY scan_result
            """
            )
            archive_by_result = {row["scan_result"]: row["count"] for row in cursor.fetchall()}

            # Cache file size
            cache_size = 0
            if os.path.exists(self.cache_path):
                cache_size = os.path.getsize(self.cache_path)

            # Oldest and newest entries (from both tables)
            cursor.execute(
                """
                SELECT MIN(scan_date) as oldest, MAX(scan_date) as newest
                FROM (
                    SELECT scan_date FROM scan_cache
                    UNION ALL
                    SELECT scan_date FROM archive_cache
                )
            """
            )
            row = cursor.fetchone()
            oldest = row["oldest"]
            newest = row["newest"]

            # Expired count (both tables)
            expired = 0
            if self.expire_days > 0:
                expire_date = datetime.now() - timedelta(days=self.expire_days)
                expire_str = expire_date.isoformat()
                cursor.execute("SELECT COUNT(*) FROM scan_cache WHERE scan_date < ?", (expire_str,))
                expired += cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM archive_cache WHERE scan_date < ?", (expire_str,))
                expired += cursor.fetchone()[0]

        return {
            "cache_path": self.cache_path,
            "cache_size_bytes": cache_size,
            "cache_size_str": self._format_size(cache_size),
            "total_entries": file_total + archive_total,
            "file_entries": file_total,
            "archive_entries": archive_total,
            "clean_files": file_by_result.get("clean", 0),
            "infected_files": file_by_result.get("infected", 0),
            "error_files": file_by_result.get("error", 0),
            "clean_archives": archive_by_result.get("clean", 0),
            "infected_archives": archive_by_result.get("infected", 0),
            "expired_entries": expired,
            "expire_days": self.expire_days,
            "oldest_entry": oldest,
            "newest_entry": newest,
        }

    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human-readable string."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f}TB"

    def vacuum(self) -> None:
        """Compact the database file."""
        conn = self._get_connection()
        conn.execute("VACUUM")

    def close(self) -> None:
        """Close the database connection."""
        if hasattr(self._local, "connection") and self._local.connection:
            self._local.connection.close()
            self._local.connection = None


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> Optional[str]:
    """Compute hash of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (default: sha256)

    Returns:
        Hex digest of the hash, or None on error
    """
    try:
        h = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, OSError):
        return None


def compute_contents_hash(entries: List[Tuple[str, int, int]], algorithm: str = "sha256") -> str:
    """Compute hash of archive contents list.

    This creates a hash based on the list of files inside an archive,
    allowing cache validation even if the archive is re-compressed.

    Args:
        entries: List of (filename, size, crc) tuples for each entry in archive
        algorithm: Hash algorithm (default: sha256)

    Returns:
        Hex digest of the contents hash
    """
    h = hashlib.new(algorithm)
    # Sort entries for consistent hash regardless of listing order
    sorted_entries = sorted(entries, key=lambda x: x[0])
    for filename, size, crc in sorted_entries:
        # Create a consistent string representation
        entry_str = f"{filename}|{size}|{crc}\n"
        h.update(entry_str.encode("utf-8"))
    return h.hexdigest()


def get_default_cache() -> ScanCache:
    """Get the default global cache instance.

    Returns:
        ScanCache instance using default location
    """
    return ScanCache()


def create_cache(
    cache_path: Optional[str] = None,
    expire_days: int = ScanCache.DEFAULT_EXPIRE_DAYS,
) -> ScanCache:
    """Factory function to create a ScanCache instance.

    Args:
        cache_path: Custom cache path (None for default)
        expire_days: Cache expiration in days (0 = never)

    Returns:
        Configured ScanCache instance
    """
    return ScanCache(cache_path=cache_path, expire_days=expire_days)
