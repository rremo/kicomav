# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Scanner Module

This module provides a high-level, easy-to-use interface for malware scanning
and archive exploration/extraction.
"""

import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple, Union

from .k2config import get_config
from .k2engine import Engine, EngineInstance
from .k2file import FileStruct, K2Tempfile
from . import k2security

# Module logger
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a file scan operation.

    Attributes:
        path: Path to the scanned file
        infected: Whether malware was detected
        malware_name: Name of detected malware (if any)
        disinfected: Whether the file was successfully disinfected
        error: Error message if scan failed
    """

    path: str
    infected: bool = False
    malware_name: Optional[str] = None
    disinfected: bool = False
    error: Optional[str] = None


# Type alias for scan callback
ScanCallback = Callable[[ScanResult], None]


# ---------------------------------------------------------------------
# Archive API Data Classes and Exceptions
# ---------------------------------------------------------------------


class ArchiveError(Exception):
    """Base exception for archive operations."""

    pass


class ArchiveNotFoundError(ArchiveError):
    """Archive file not found."""

    pass


class ArchiveFormatError(ArchiveError):
    """Unrecognized or corrupt archive format."""

    pass


class ArchivePasswordError(ArchiveError):
    """Password required or incorrect."""

    pass


class ArchiveSecurityError(ArchiveError):
    """Security violation (path traversal, etc.)."""

    pass


class ArchiveExtractionError(ArchiveError):
    """Failed to extract archive entry."""

    pass


@dataclass
class ArchiveEntry:
    """Represents a single file entry within an archive.

    Attributes:
        path: Relative path within the archive (normalized with forward slashes)
        filename: Base filename (e.g., "file.txt")
        archive_path: Absolute path to the containing archive
        depth: Nesting depth (0 for direct children, 1+ for nested archives)
        engine_id: Archive engine identifier (e.g., "arc_zip", "arc_7z")
        size: Uncompressed file size in bytes (if available, else -1)
        is_encrypted: Whether the entry is password-protected
        parent_entries: List of parent ArchiveEntry objects for nested archives
    """

    path: str
    filename: str
    archive_path: str
    depth: int = 0
    engine_id: str = ""
    size: int = -1
    is_encrypted: bool = False
    parent_entries: List["ArchiveEntry"] = field(default_factory=list)
    # Internal: stores original FileStruct for direct extraction
    _file_struct: Optional[FileStruct] = field(default=None, repr=False, compare=False)

    def get_full_path(self) -> str:
        """Get the full display path including parent archives (normalized)."""
        # Normalize path (backslash to forward slash for display)
        normalized_path = self.path.replace("\\", "/")
        if self.parent_entries:
            parent_path = "/".join(e.path.replace("\\", "/") for e in self.parent_entries)
            return f"{parent_path}/{normalized_path}"
        return normalized_path


@dataclass
class ExtractionResult:
    """Result of an archive extraction operation.

    Attributes:
        success: Overall success status
        output_dir: Directory where files were extracted
        extracted_files: List of (output_path, ArchiveEntry) tuples
        failed_entries: List of (ArchiveEntry, error_message) tuples
        total_files: Total number of files in archive
        extracted_count: Number of successfully extracted files
        failed_count: Number of failed extractions
        log_file: Path to the extraction log file (if created)
    """

    success: bool
    output_dir: str
    extracted_files: List[Tuple[str, "ArchiveEntry"]] = field(default_factory=list)
    failed_entries: List[Tuple["ArchiveEntry", str]] = field(default_factory=list)
    total_files: int = 0
    extracted_count: int = 0
    failed_count: int = 0
    log_file: Optional[str] = None


@dataclass
class ArchiveInfo:
    """Metadata about an archive file.

    Attributes:
        path: Absolute path to the archive
        format_type: Archive format (e.g., "zip", "7z", "rar")
        engine_id: Engine identifier used to process this archive
        total_entries: Total number of entries
        nested_archives: Count of nested archive files
        is_encrypted: Whether archive has encrypted content
        error: Error message if archive couldn't be processed
    """

    path: str
    format_type: str = ""
    engine_id: str = ""
    total_entries: int = 0
    nested_archives: int = 0
    is_encrypted: bool = False
    error: Optional[str] = None


# Type alias for archive callbacks
ArchiveEntryCallback = Callable[["ArchiveEntry"], None]
ExtractionCallback = Callable[["ArchiveEntry", str], None]

# Known archive extensions for nested archive detection
ARCHIVE_EXTENSIONS = {
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".cab",
    ".egg",
    ".alz",
    ".iso",
    ".arj",
    ".lzh",
    ".ace",
}


class Scanner:
    """High-level malware scanner interface.

    This class provides a simplified API for scanning files and directories
    for malware. It handles engine initialization and cleanup automatically.

    Example:
        # Simple file scan
        with Scanner() as scanner:
            result = scanner.scan_file("/path/to/file.exe")
            if result.infected:
                print(f"Detected: {result.malware_name}")

        # Directory scan with callback
        with Scanner() as scanner:
            results = scanner.scan_directory("/path/to/folder")
            for result in results:
                if result.infected:
                    print(f"{result.path}: {result.malware_name}")
    """

    def __init__(
        self,
        plugins_path: Optional[str] = None,
        verbose: bool = False,
    ):
        """Initialize the Scanner.

        Args:
            plugins_path: Path to plugins directory. If None, attempts to find
                          plugins in the default location relative to the package.
            verbose: Enable verbose output for debugging
        """
        self._engine: Optional[Engine] = None
        self._instance: Optional[EngineInstance] = None
        self._plugins_path = plugins_path
        self._verbose = verbose
        self._initialized = False

    def _find_plugins_path(self) -> Optional[str]:
        """Find the plugins directory.

        Returns:
            Path to plugins directory or None if not found
        """
        if self._plugins_path:
            return self._plugins_path

        # Try to find plugins relative to the package
        try:
            # Get the path of the kicomav package
            import kicomav

            package_dir = os.path.dirname(os.path.abspath(kicomav.__file__))
            plugins_dir = os.path.join(package_dir, "plugins")

            if os.path.isdir(plugins_dir):
                return plugins_dir
        except Exception:
            pass

        # Try common installation paths
        common_paths = [
            os.path.join(os.path.dirname(__file__), "..", "plugins"),
            "/usr/local/share/kicomav/plugins",
            "/usr/share/kicomav/plugins",
        ]

        for path in common_paths:
            abs_path = os.path.abspath(path)
            if os.path.isdir(abs_path):
                return abs_path

        return None

    def _ensure_initialized(self) -> bool:
        """Ensure the scanner engine is initialized.

        Returns:
            True if initialization succeeded, False otherwise
        """
        if self._initialized and self._instance is not None:
            return True

        try:
            # Find plugins path
            plugins_path = self._find_plugins_path()
            if not plugins_path:
                logger.error("Could not find plugins directory")
                return False

            # Create engine
            self._engine = Engine(verbose=self._verbose)

            # Set plugins
            if not self._engine.set_plugins(plugins_path):
                logger.error("Failed to load plugins from %s", plugins_path)
                return False

            # Create instance
            self._instance = self._engine.create_instance()
            if self._instance is None:
                logger.error("Failed to create engine instance")
                return False

            # Initialize instance
            if not self._instance.init():
                logger.error("Failed to initialize engine instance")
                return False

            self._initialized = True
            return True

        except Exception as e:
            logger.exception("Failed to initialize scanner: %s", e)
            return False

    def scan_file(self, path: Union[str, Path], disinfect: bool = False) -> ScanResult:
        """Scan a single file for malware.

        Args:
            path: Path to the file to scan
            disinfect: If True, attempt to disinfect infected files

        Returns:
            ScanResult with scan details
        """
        path_str = str(path)
        result = ScanResult(path=path_str)

        # Ensure file exists
        if not os.path.isfile(path_str):
            result.error = "File not found"
            return result

        # Initialize if needed
        if not self._ensure_initialized():
            result.error = "Failed to initialize scanner"
            return result

        try:
            # Track scan results
            scan_result = {"infected": False, "malware_name": None, "disinfected": False}

            # Callback to capture scan results
            def scan_callback(ret_value):
                if ret_value.get("result"):
                    scan_result["infected"] = True
                    scan_result["malware_name"] = ret_value.get("virus_name", "Unknown")

            # Callback for disinfection results
            def disinfect_callback(ret_value, disinfect_result):
                if disinfect_result:
                    scan_result["disinfected"] = True

            # Configure options
            self._instance.set_options({"opt_dis": disinfect})

            # Perform scan
            if disinfect:
                self._instance.scan(path_str, scan_callback, disinfect_callback)
            else:
                self._instance.scan(path_str, scan_callback)

            # Update result
            result.infected = scan_result["infected"]
            result.malware_name = scan_result["malware_name"]
            result.disinfected = scan_result["disinfected"]

        except Exception as e:
            result.error = str(e)
            logger.exception("Error scanning file %s: %s", path_str, e)

        return result

    def scan_directory(
        self,
        path: Union[str, Path],
        recursive: bool = True,
        disinfect: bool = False,
        callback: Optional[ScanCallback] = None,
    ) -> List[ScanResult]:
        """Scan a directory for malware.

        Args:
            path: Path to the directory to scan
            recursive: If True, scan subdirectories recursively
            disinfect: If True, attempt to disinfect infected files
            callback: Optional callback called for each scanned file

        Returns:
            List of ScanResult for all scanned files
        """
        path_str = str(path)
        results: List[ScanResult] = []

        # Ensure directory exists
        if not os.path.isdir(path_str):
            results.append(ScanResult(path=path_str, error="Directory not found"))
            return results

        # Initialize if needed
        if not self._ensure_initialized():
            results.append(ScanResult(path=path_str, error="Failed to initialize scanner"))
            return results

        try:
            # Collect files to scan
            files_to_scan = []
            if recursive:
                for root, dirs, files in os.walk(path_str):
                    for fname in files:
                        files_to_scan.append(os.path.join(root, fname))
            else:
                for fname in os.listdir(path_str):
                    fpath = os.path.join(path_str, fname)
                    if os.path.isfile(fpath):
                        files_to_scan.append(fpath)

            # Scan each file
            for fpath in files_to_scan:
                result = self.scan_file(fpath, disinfect=disinfect)
                results.append(result)

                if callback:
                    callback(result)

        except Exception as e:
            logger.exception("Error scanning directory %s: %s", path_str, e)
            results.append(ScanResult(path=path_str, error=str(e)))

        return results

    def get_statistics(self) -> dict:
        """Get scan statistics from the current session.

        Returns:
            Dictionary with scan statistics
        """
        if not self._instance:
            return {}

        try:
            result = self._instance.result
            return {
                "files_scanned": result.get("files", 0),
                "infected": result.get("infected_files", 0),
                "disinfected": result.get("cured_files", 0),
                "warnings": result.get("io_errors", 0),
            }
        except Exception:
            return {}

    def close(self) -> None:
        """Close the scanner and release resources."""
        if self._instance:
            try:
                self._instance.uninit()
            except Exception as e:
                logger.debug("Error during uninit: %s", e)
            self._instance = None

        if self._engine:
            try:
                del self._engine
            except Exception as e:
                logger.debug("Error during engine cleanup: %s", e)
            self._engine = None

        self._initialized = False

    def __enter__(self) -> "Scanner":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()

    def __del__(self) -> None:
        """Destructor to ensure cleanup."""
        self.close()

    # -----------------------------------------------------------------
    # Archive Exploration and Extraction API
    # -----------------------------------------------------------------

    def _is_archive_extension(self, filename: str) -> bool:
        """Check if filename has a known archive extension."""
        return Path(filename).suffix.lower() in ARCHIVE_EXTENSIONS

    def _detect_archive_format(self, fileformat: dict) -> Tuple[str, str]:
        """Detect archive format from fileformat dict.

        Returns:
            Tuple of (format_type, engine_id)
        """
        # Map fileformat keys to human-readable format names
        format_map = {
            "ff_zip": ("zip", "arc_zip"),
            "ff_7z": ("7z", "arc_7z"),
            "ff_rar": ("rar", "arc_rar"),
            "ff_tar": ("tar", "arc_tar"),
            "ff_gzip": ("gzip", "arc_gzip"),
            "ff_bz2": ("bz2", "arc_bz2"),
            "ff_cab": ("cab", "arc_cab"),
            "ff_egg": ("egg", "arc_egg"),
            "ff_alz": ("alz", "arc_alz"),
            "ff_arj": ("arj", "arc_arj"),
            "ff_lzh": ("lzh", "arc_lzh"),
            "ff_ace": ("ace", "arc_ace"),
            "ff_iso": ("iso", "arc_iso"),
            "ff_zlib": ("zlib", "arc_zlib"),
            "ff_embed_ole": ("embed_ole", "arc_embed_ole"),
            "ff_attach": ("attach", "arc_attach"),
            "ff_pe": ("pe", ""),  # PE can have embedded archives (UPX, attach, etc.)
            "ff_pyz": ("pyz", "arc_pyz"),
            "ff_nsis": ("nsis", "arc_nsis"),
            "ff_inno": ("inno", "arc_inno"),
            "ff_msi": ("msi", "arc_msi"),
            "ff_hwp": ("hwp", "arc_hwp"),
            "ff_hwpx": ("hwpx", "arc_hwpx"),
            "ff_ole": ("ole", "arc_ole"),
            "ff_eml": ("eml", "arc_eml"),
        }

        for ff_key, (fmt_type, engine_id) in format_map.items():
            if ff_key in fileformat:
                return fmt_type, engine_id

        return "", ""

    def _detect_format_from_arclist(self, arc_list: list) -> Tuple[str, str]:
        """Detect format from arclist results when format detection fails.

        Returns:
            Tuple of (format_type, engine_id) based on first entry's engine
        """
        if not arc_list:
            return "", ""

        # Get engine ID from first entry
        first_entry = arc_list[0]
        engine_id = first_entry.get_archive_engine_name()

        # Map engine IDs to format types
        engine_format_map = {
            "arc_zip": "zip",
            "arc_7z": "7z",
            "arc_rar": "rar",
            "arc_tar": "tar",
            "arc_gzip": "gzip",
            "arc_bz2": "bz2",
            "arc_cab": "cab",
            "arc_egg": "egg",
            "arc_alz": "alz",
            "arc_attach": "attach",
            "arc_pyz": "pyz",
            "arc_nsis": "nsis",
            "arc_inno": "inno",
            "arc_msi": "msi",
            "arc_hwp": "hwp",
            "arc_hwpx": "hwpx",
            "arc_ole": "ole",
            "arc_eml": "eml",
            "arc_zlib": "zlib",
            "arc_embed_ole": "embed_ole",
        }

        # Handle special cases like "arc_upx!nrv2b" -> "upx"
        base_engine = engine_id.split("!")[0] if "!" in engine_id else engine_id
        # Handle "arc_attach:offset:size" format
        base_engine = base_engine.split(":")[0] if ":" in base_engine else base_engine

        format_type = engine_format_map.get(base_engine, base_engine.replace("arc_", ""))

        return format_type, engine_id

    def get_archive_info(
        self,
        path: Union[str, Path],
        password: Optional[str] = None,
        recursive: bool = True,
    ) -> ArchiveInfo:
        """Get information about an archive file.

        By default, recursively explores nested archives to get accurate counts.

        Args:
            path: Path to the archive file
            password: Optional password for encrypted archives
            recursive: If True (default), explore nested archives for accurate counts

        Returns:
            ArchiveInfo with archive metadata

        Raises:
            ArchiveNotFoundError: If archive file doesn't exist

        Example:
            with Scanner() as scanner:
                info = scanner.get_archive_info("/path/to/archive.zip")
                print(f"Format: {info.format_type}")
                print(f"Total entries: {info.total_entries}")
        """
        # Use list_archive to get accurate counts (including nested archives)
        info, _ = self.list_archive(path, recursive=recursive, password=password)
        return info

    def list_archive(
        self,
        path: Union[str, Path],
        recursive: bool = True,
        max_depth: int = 10,
        password: Optional[str] = None,
        callback: Optional[ArchiveEntryCallback] = None,
    ) -> Tuple[ArchiveInfo, List[ArchiveEntry]]:
        """List contents of an archive file.

        Recursively explores archive contents including nested archives.

        Args:
            path: Path to the archive file
            recursive: If True, explore nested archives recursively
            max_depth: Maximum nesting depth to explore (default: 10)
            password: Optional password for encrypted archives
            callback: Optional callback called for each discovered entry

        Returns:
            Tuple of (ArchiveInfo, List[ArchiveEntry])

        Raises:
            ArchiveNotFoundError: If archive file doesn't exist
            ArchiveFormatError: If file is not a recognized archive format

        Example:
            with Scanner() as scanner:
                info, entries = scanner.list_archive("/path/to/archive.zip")
                for entry in entries:
                    print(f"{entry.get_full_path()} ({entry.size} bytes)")
        """
        path_str = str(path)
        abs_path = os.path.abspath(path_str)

        # Check file exists
        if not os.path.isfile(abs_path):
            raise ArchiveNotFoundError(f"Archive file not found: {abs_path}")

        # Initialize if needed
        if not self._ensure_initialized():
            info = ArchiveInfo(path=abs_path, error="Failed to initialize scanner")
            return info, []

        # Create temp file manager for nested archive extraction
        temp_manager = K2Tempfile()

        try:
            # Enable archive exploration and set password if provided
            options = {"opt_arc": True}
            if password:
                options["opt_password"] = password
            self._instance.set_options(options)

            # Get archive info first
            file_struct = FileStruct(abs_path)
            fileformat = self._instance.format(file_struct)

            if not fileformat:
                raise ArchiveFormatError(f"Unrecognized file format: {abs_path}")

            # Try to detect format from fileformat dict
            format_type, engine_id = self._detect_archive_format(fileformat)

            # If format detection fails, check if arclist returns anything
            # This handles cases like PE files with embedded archives (UPX, attach, etc.)
            if not format_type:
                arc_list = self._instance.arclist(file_struct, fileformat)
                if arc_list:
                    format_type, engine_id = self._detect_format_from_arclist(arc_list)
                else:
                    raise ArchiveFormatError(f"Not a recognized archive format: {abs_path}")

            # List archive contents
            entries = self._list_archive_internal(
                abs_path=abs_path,
                file_struct=file_struct,
                fileformat=fileformat,
                depth=0,
                max_depth=max_depth,
                recursive=recursive,
                password=password,
                parent_entries=[],
                callback=callback,
                temp_manager=temp_manager,
            )

            # Count nested archives - count unique entries that have children
            nested_parents = set()
            for e in entries:
                if e.depth > 0 and e.parent_entries:
                    nested_parents.add(e.parent_entries[-1].path)
            nested_count = len(nested_parents)

            info = ArchiveInfo(
                path=abs_path,
                format_type=format_type,
                engine_id=engine_id,
                total_entries=len(entries),
                nested_archives=nested_count,
            )

            return info, entries

        except (ArchiveNotFoundError, ArchiveFormatError):
            raise
        except Exception as e:
            logger.exception("Error listing archive %s: %s", abs_path, e)
            info = ArchiveInfo(path=abs_path, error=str(e))
            return info, []
        finally:
            # Cleanup temp files
            temp_manager.removetempdir()

    def _list_archive_internal(
        self,
        abs_path: str,
        file_struct: FileStruct,
        fileformat: dict,
        depth: int,
        max_depth: int,
        recursive: bool,
        password: Optional[str],
        parent_entries: List[ArchiveEntry],
        callback: Optional[ArchiveEntryCallback],
        temp_manager: K2Tempfile,
    ) -> List[ArchiveEntry]:
        """Internal recursive archive listing."""
        entries = []

        # Get archive file list from engine
        arc_list = self._instance.arclist(file_struct, fileformat)

        for fs in arc_list:
            entry_name = fs.get_filename_in_archive()
            engine_id = fs.get_archive_engine_name()

            # Create ArchiveEntry (store FileStruct for direct extraction)
            entry = ArchiveEntry(
                path=entry_name,
                filename=os.path.basename(entry_name),
                archive_path=abs_path,
                depth=depth,
                engine_id=engine_id,
                parent_entries=list(parent_entries),
                _file_struct=fs,
            )

            entries.append(entry)

            if callback:
                callback(entry)

            # Check for nested archive - extract and check if it has further archives
            # This handles cases like PE -> Attached -> PYZ, not just file extensions
            if recursive and depth < max_depth:
                try:
                    # Extract entry to temp file
                    success, result = self._instance.unarc(fs)
                    if success and result:
                        temp_path = result.get_filename()
                        if temp_path and os.path.isfile(temp_path):
                            # Use the result FileStruct directly - it preserves additional_filename
                            # which is needed for format detection (e.g., carch.py checks for "Attached")
                            nested_struct = result
                            nested_format = self._instance.format(nested_struct)

                            if nested_format:
                                # Check if extracted file has further archives
                                nested_arc_list = self._instance.arclist(nested_struct, nested_format)
                                if nested_arc_list:
                                    # Recursively list nested archive
                                    nested_entries = self._list_archive_internal(
                                        abs_path=abs_path,
                                        file_struct=nested_struct,
                                        fileformat=nested_format,
                                        depth=depth + 1,
                                        max_depth=max_depth,
                                        recursive=recursive,
                                        password=password,
                                        parent_entries=parent_entries + [entry],
                                        callback=callback,
                                        temp_manager=temp_manager,
                                    )
                                    entries.extend(nested_entries)
                except Exception as e:
                    logger.debug("Failed to explore nested archive %s: %s", entry_name, e)

        return entries

    def _extract_nested_entry(
        self,
        archive_path: str,
        entry: ArchiveEntry,
        password: Optional[str] = None,
    ) -> Optional[bytes]:
        """Extract a nested entry by traversing parent chain.

        For nested archives, the stored _file_struct references temp files
        that no longer exist. This method extracts from the original archive
        through each parent to reach the target entry.

        Args:
            archive_path: Path to the original archive
            entry: The nested ArchiveEntry to extract
            password: Optional password

        Returns:
            Extracted file data as bytes, or None on failure
        """
        try:
            # Build extraction path: [parent1, parent2, ..., entry]
            extraction_chain = list(entry.parent_entries) + [entry]

            # Start with the original archive
            current_struct = FileStruct(archive_path)
            current_format = self._instance.format(current_struct)
            if not current_format:
                return None

            # Extract through each level
            for i, chain_entry in enumerate(extraction_chain):
                # Get archive list at current level
                arc_list = self._instance.arclist(current_struct, current_format)

                # Find matching entry by path
                target_fs = None
                for fs in arc_list:
                    fname = fs.get_filename_in_archive()
                    if fname == chain_entry.path:
                        target_fs = fs
                        break
                    # Try normalized match
                    if fname.replace("\\", "/") == chain_entry.path.replace("\\", "/"):
                        target_fs = fs
                        break

                if not target_fs:
                    logger.debug("Entry not found: %s", chain_entry.path)
                    return None

                # Extract this entry
                success, result = self._instance.unarc(target_fs)
                if not success or not result:
                    return None

                temp_path = result.get_filename()
                if not temp_path or not os.path.isfile(temp_path):
                    return None

                # Is this the final entry?
                if i == len(extraction_chain) - 1:
                    # Read and return file contents
                    with open(temp_path, "rb") as f:
                        return f.read()

                # Otherwise, use extracted file as next archive
                current_struct = result
                current_format = self._instance.format(current_struct)
                if not current_format:
                    # Not an archive, but not the final entry - error
                    return None

        except Exception as e:
            logger.debug("Failed to extract nested entry %s: %s", entry.get_full_path(), e)
            return None

        return None

    def read_archive(
        self,
        path: Union[str, Path],
        entry_path: str,
        password: Optional[str] = None,
    ) -> Optional[bytes]:
        """Read a single file from an archive into memory.

        Extracts the specified file from the archive and returns its
        contents as bytes without writing to disk.

        For nested archives, use "/" to separate archive levels:
            "Attached/Include/pyconfig.h"

        Note: Backslashes in filenames are normalized to forward slashes
        for matching (e.g., "Include\\pyconfig.h" matches "Include/pyconfig.h").

        Args:
            path: Path to the archive file
            entry_path: Path to the file within the archive (use "/" separator)
            password: Optional password for encrypted archives

        Returns:
            File contents as bytes, or None if extraction failed

        Raises:
            ArchiveNotFoundError: If archive doesn't exist
            ArchiveSecurityError: If entry_path contains path traversal

        Example:
            with Scanner() as scanner:
                data = scanner.read_archive("/path/to/archive.zip", "config.json")
        """
        path_str = str(path)
        abs_path = os.path.abspath(path_str)

        # Check file exists
        if not os.path.isfile(abs_path):
            raise ArchiveNotFoundError(f"Archive file not found: {abs_path}")

        # Security check on entry path
        if not k2security.is_safe_archive_member(entry_path):
            raise ArchiveSecurityError(f"Unsafe entry path: {entry_path}")

        # Initialize if needed
        if not self._ensure_initialized():
            return None

        try:
            # Get all entries from archive (includes nested)
            info, entries = self.list_archive(
                abs_path,
                recursive=True,
                password=password,
            )

            # Normalize entry_path for comparison (backslash to forward slash)
            normalized_entry_path = entry_path.replace("\\", "/")

            # Find matching entry by comparing normalized full paths
            target_entry = None
            for entry in entries:
                # get_full_path() already normalizes backslashes to forward slashes
                if entry.get_full_path() == normalized_entry_path:
                    target_entry = entry
                    break

            if target_entry is None:
                logger.debug("Entry not found in archive: %s", entry_path)
                return None

            # Extract using stored FileStruct (same as extract_archive)
            if target_entry._file_struct is None:
                logger.debug("No FileStruct available for entry: %s", entry_path)
                return None

            success, unarc_result = self._instance.unarc(target_entry._file_struct)
            if not success or not unarc_result:
                return None

            temp_path = unarc_result.get_filename()
            if not temp_path or not os.path.isfile(temp_path):
                return None

            # Read and return file contents
            with open(temp_path, "rb") as f:
                return f.read()

        except (ArchiveNotFoundError, ArchiveSecurityError):
            raise
        except Exception as e:
            logger.exception("Error reading archive entry %s/%s: %s", abs_path, entry_path, e)
            return None

    def extract_archive(
        self,
        path: Union[str, Path],
        output_dir: Union[str, Path],
        recursive: bool = True,
        max_depth: int = 10,
        password: Optional[str] = None,
        preserve_structure: bool = True,
        create_log: bool = True,
        callback: Optional[ExtractionCallback] = None,
    ) -> ExtractionResult:
        """Extract archive contents to a directory.

        Extracts all files from the archive (and nested archives if recursive)
        to the specified output directory.

        Args:
            path: Path to the archive file
            output_dir: Directory to extract files into
            recursive: If True, extract nested archives recursively
            max_depth: Maximum nesting depth to process (default: 10)
            password: Optional password for encrypted archives
            preserve_structure: If True, preserve directory structure within archive
            create_log: If True, create an extraction log file (archive_info.log)
            callback: Optional callback called after each extraction (entry, output_path)

        Returns:
            ExtractionResult with extraction details

        Raises:
            ArchiveNotFoundError: If archive file doesn't exist
            PermissionError: If output directory cannot be written to

        Example:
            with Scanner() as scanner:
                result = scanner.extract_archive(
                    "/path/to/archive.zip",
                    "/output/folder"
                )
                print(f"Extracted {result.extracted_count} files")
        """
        path_str = str(path)
        abs_path = os.path.abspath(path_str)
        output_str = str(output_dir)
        abs_output = os.path.abspath(output_str)

        # Initialize result
        result = ExtractionResult(success=False, output_dir=abs_output)

        # Check archive exists
        if not os.path.isfile(abs_path):
            raise ArchiveNotFoundError(f"Archive file not found: {abs_path}")

        # Create output directory if needed
        os.makedirs(abs_output, exist_ok=True)

        # Initialize if needed
        if not self._ensure_initialized():
            result.failed_entries.append(
                (ArchiveEntry(path="", filename="", archive_path=abs_path), "Failed to initialize scanner")
            )
            return result

        # Create temp file manager
        temp_manager = K2Tempfile()
        log_entries = []

        try:
            # Enable archive exploration and set password if provided
            options = {"opt_arc": True}
            if password:
                options["opt_password"] = password
            self._instance.set_options(options)

            # List all entries
            info, entries = self.list_archive(
                abs_path,
                recursive=recursive,
                max_depth=max_depth,
                password=password,
            )

            result.total_files = len(entries)

            # Ensure k2engine temp directory exists (may have been removed by list_archive)
            # All K2Tempfile instances share the same PID-based directory
            engine_temp = self._instance.temp_path
            if not os.path.exists(engine_temp.temp_path):
                os.makedirs(engine_temp.temp_path, exist_ok=True)

            # Identify entries that have nested content (these become directories, not files)
            nested_parent_paths = set()
            for e in entries:
                if e.parent_entries:
                    # All parent entries should become directories
                    for i in range(len(e.parent_entries)):
                        parent_path = "/".join(p.path for p in e.parent_entries[: i + 1])
                        nested_parent_paths.add(parent_path)

            # Extract each entry
            for entry in entries:
                try:
                    # Security check
                    if not k2security.is_safe_archive_member(entry.path):
                        result.failed_entries.append((entry, "Path traversal detected"))
                        result.failed_count += 1
                        continue

                    # Build full path for this entry
                    entry_full_path = entry.get_full_path()

                    # Handle entries that are parent archives (contain nested content)
                    if entry_full_path in nested_parent_paths:
                        if preserve_structure:
                            # Create directory instead of extracting as file
                            dir_path = os.path.join(abs_output, entry_full_path.replace("/", os.sep))
                            os.makedirs(dir_path, exist_ok=True)
                            continue
                        # For flat structure, extract the parent archive as a file too
                        # (don't skip - fall through to extraction)

                    # Extract entry content
                    # For nested archives, we must extract from parent to child sequentially
                    # because _file_struct references temp files that no longer exist
                    if entry.parent_entries:
                        # Nested entry - extract through parent chain
                        data = self._extract_nested_entry(abs_path, entry, password)
                        if data is None:
                            result.failed_entries.append((entry, "Failed to extract nested entry"))
                            result.failed_count += 1
                            continue
                    else:
                        # Top-level entry - use stored FileStruct
                        if entry._file_struct is None:
                            result.failed_entries.append((entry, "No FileStruct available"))
                            result.failed_count += 1
                            continue

                        success, unarc_result = self._instance.unarc(entry._file_struct)
                        if not success or not unarc_result:
                            result.failed_entries.append((entry, "Failed to extract"))
                            result.failed_count += 1
                            continue

                        temp_path = unarc_result.get_filename()
                        if not temp_path or not os.path.isfile(temp_path):
                            result.failed_entries.append((entry, "Temp file not found"))
                            result.failed_count += 1
                            continue

                        # Read extracted file data
                        with open(temp_path, "rb") as f:
                            data = f.read()

                    # Sanitize filename for filesystem (replace invalid chars)
                    safe_path = entry_full_path.replace("\\", "/")
                    # Replace Windows-invalid characters: < > : " | ? *
                    for char in '<>:"|?*':
                        safe_path = safe_path.replace(char, "_")

                    # Determine output path
                    if preserve_structure:
                        output_path = os.path.join(abs_output, safe_path.replace("/", os.sep))
                    else:
                        # Flat structure - use temp-like naming to avoid conflicts
                        output_path = temp_manager.mktemp()
                        # Move to output dir
                        final_name = os.path.basename(output_path)
                        output_path = os.path.join(abs_output, final_name)

                    # Ensure parent directory exists
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)

                    # Write file
                    with open(output_path, "wb") as f:
                        f.write(data)

                    result.extracted_files.append((output_path, entry))
                    result.extracted_count += 1

                    # Record for log
                    log_entries.append((os.path.basename(output_path), entry_full_path))

                    if callback:
                        callback(entry, output_path)

                except Exception as e:
                    result.failed_entries.append((entry, str(e)))
                    result.failed_count += 1
                    logger.debug("Failed to extract %s: %s", entry.path, e)

            # Create log file if requested
            if create_log and log_entries:
                log_path = os.path.join(abs_output, "archive_info.log")
                with open(log_path, "w", encoding="utf-8") as f:
                    for temp_name, orig_path in log_entries:
                        f.write(f"{temp_name} : {orig_path}\n")
                result.log_file = log_path

            result.success = result.extracted_count > 0

        except Exception as e:
            logger.exception("Error extracting archive %s: %s", abs_path, e)
            result.failed_entries.append((ArchiveEntry(path="", filename="", archive_path=abs_path), str(e)))
        finally:
            temp_manager.removetempdir()

        return result
