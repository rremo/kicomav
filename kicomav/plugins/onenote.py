# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
OneNote Archive Engine Plugin

This plugin handles Microsoft OneNote (.one) files for extracting embedded files.
Based on MS-ONESTORE specification and one-extract by Volexity.

References:
- https://github.com/volexity/one-extract
- https://blog.nviso.eu/2023/02/27/onenote-embedded-file-abuse/
- MS-ONESTORE: OneNote Revision Store File Format
"""

import struct
import logging

from kicomav.kavcore import k2security
from kicomav.kavcore.k2plugin_base import ArchivePluginBase

# Logger
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# OneNote File Format Constants
# -------------------------------------------------------------------------

# OneNote file header GUID: {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
ONENOTE_HEADER_MAGIC = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3")

# Embedded file GUID (FileDataStoreObject): {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
EMBEDDED_FILE_MAGIC = bytes.fromhex("E716E3BD65261145A4C48D4D0B7A9EAC")

# File signature to extension mapping
FILE_SIGNATURES = {
    b"\xff\xd8\xff": ".jpg",  # JPEG
    b"\x89PNG": ".png",  # PNG
    b"GIF8": ".gif",  # GIF
    b"PK\x03\x04": ".zip",  # ZIP/Office
    b"PK\x05\x06": ".zip",  # ZIP empty
    b"\xd0\xcf\x11\xe0": ".doc",  # OLE (DOC, XLS, PPT)
    b"%PDF": ".pdf",  # PDF
    b"MZ": ".exe",  # PE executable
    b"\x7fELF": ".elf",  # ELF executable
    b"Rar!": ".rar",  # RAR
    b"\x1f\x8b": ".gz",  # GZIP
    b"BZh": ".bz2",  # BZIP2
    b"\xfd7zXZ": ".xz",  # XZ
    b"7z\xbc\xaf": ".7z",  # 7Z
    b"<html": ".html",  # HTML
    b"<!DOCTYPE": ".html",  # HTML
    b"<?xml": ".xml",  # XML
}

# Filename property marker (LCID 0x0409 = English US)
FILENAME_MARKER = bytes.fromhex("09040000")


# -------------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------------


def is_onenote(data):
    """Check if data is a valid OneNote file.

    Args:
        data: File data (at least 16 bytes)

    Returns:
        True if valid OneNote file, False otherwise
    """
    if len(data) < 16:
        return False
    return data[:16] == ONENOTE_HEADER_MAGIC


def get_extension_from_signature(data):
    """Determine file extension based on file signature.

    Args:
        data: File data (at least first few bytes)

    Returns:
        File extension string (e.g., ".jpg", ".png")
    """
    for sig, ext in FILE_SIGNATURES.items():
        if data[: len(sig)] == sig:
            return ext
    return ".bin"


def extract_filenames(data):
    """Extract original filenames from OneNote data.

    OneNote stores embedded filenames as UTF-16 LE strings preceded by
    the LCID marker (0x0409 for English) and a 4-byte length field.

    Args:
        data: OneNote file data

    Returns:
        List of dicts with 'offset', 'filename' keys, sorted by offset
    """
    filenames = []
    pos = 0

    while True:
        pos = data.find(FILENAME_MARKER, pos)
        if pos == -1:
            break

        try:
            # Read string length (4 bytes, little-endian, in bytes)
            str_len = struct.unpack("<I", data[pos + 4 : pos + 8])[0]

            # Sanity check for length
            if str_len < 4 or str_len > 1000 or pos + 8 + str_len > len(data):
                pos += 4
                continue

            # Extract and decode UTF-16 LE string
            str_data = data[pos + 8 : pos + 8 + str_len]
            filename = str_data.decode("utf-16-le", errors="strict").rstrip("\x00")

            # Validate filename (must have extension and valid characters)
            if "." in filename and len(filename) > 4 and not any(c in filename for c in '<>|"?*\x00\n\r'):
                filenames.append(
                    {
                        "offset": pos + 8,  # Offset of the string itself
                        "filename": filename,
                    }
                )

            pos += 8 + str_len
        except (struct.error, UnicodeDecodeError):
            pos += 4

    # Sort by offset
    filenames.sort(key=lambda x: x["offset"])
    return filenames


def match_filename_to_embedded(embedded_offset, filenames, file_extension):
    """Find the best matching original filename for an embedded file.

    Uses a heuristic approach:
    1. Find filenames that appear before the embedded file offset
    2. Match filenames with the same extension as determined by signature
    3. Return None if no matching extension found (will fall back to signature-based name)

    Args:
        embedded_offset: Offset of the embedded file GUID
        filenames: List of filename dicts from extract_filenames()
        file_extension: Extension determined from file signature (e.g., ".jpg")

    Returns:
        Original filename string, or None if no match found
    """
    if not filenames:
        return None

    # Filter filenames that appear before the embedded file
    candidates = [f for f in filenames if f["offset"] < embedded_offset]
    if not candidates:
        return None

    # Find filename with matching extension
    ext_lower = file_extension.lower()
    for candidate in reversed(candidates):  # Check from nearest to farthest
        fname = candidate["filename"]
        if fname.lower().endswith(ext_lower):
            return fname

    # Handle special cases (e.g., .doc for OLE files)
    ole_extensions = {".doc", ".xls", ".ppt", ".msi", ".ole"}
    if ext_lower in ole_extensions:
        for candidate in reversed(candidates):
            fname = candidate["filename"]
            fname_ext = fname[fname.rfind(".") :].lower() if "." in fname else ""
            if fname_ext in ole_extensions:
                return fname

    # No matching extension found - return None to use signature-based name
    return None


def extract_embedded_files(data, include_filenames=True):
    """Extract embedded files from OneNote data.

    Args:
        data: OneNote file data
        include_filenames: If True, attempt to extract original filenames

    Returns:
        List of dicts with 'offset', 'size', 'data', 'original_filename' keys
    """
    files = []
    pos = 0

    # Extract filenames first if requested
    filenames = extract_filenames(data) if include_filenames else []

    while True:
        pos = data.find(EMBEDDED_FILE_MAGIC, pos)
        if pos == -1:
            break

        try:
            # Read file size (8 bytes at offset +16, little-endian)
            size = struct.unpack("<Q", data[pos + 16 : pos + 24])[0]

            # Sanity check for size
            if size > len(data) - pos - 36:
                logger.warning("Invalid embedded file size at offset 0x%X", pos)
                pos += 16
                continue

            # Extract file data (starts at offset +36)
            file_start = pos + 36
            file_data = data[file_start : file_start + size]

            # Determine file extension from signature
            ext = get_extension_from_signature(file_data)

            # Try to match original filename
            original_filename = None
            if include_filenames and filenames:
                original_filename = match_filename_to_embedded(pos, filenames, ext)

            files.append(
                {
                    "offset": pos,
                    "size": size,
                    "data": file_data,
                    "original_filename": original_filename,
                }
            )

            pos = file_start + size
        except (struct.error, IndexError) as e:
            logger.warning("Error extracting embedded file at offset 0x%X: %s", pos, e)
            pos += 16

    return files


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """OneNote archive handler plugin.

    This plugin provides functionality for:
    - Detecting Microsoft OneNote (.one) file format
    - Listing embedded files within OneNote files
    - Extracting embedded files for scanning
    """

    def __init__(self):
        """Initialize the OneNote plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="OneNote Archive Engine",
            kmd_name="onenote",
        )
        self.embedded_files = {}  # Cache for embedded files
        self.filename_to_index = {}  # Map filename to index for unarc()

    def _custom_init(self) -> int:
        """Custom initialization for OneNote plugin.

        Returns:
            0 for success
        """
        return 0

    def _custom_uninit(self) -> int:
        """Custom cleanup for OneNote plugin.

        Returns:
            0 for success
        """
        self.arcclose()
        return 0

    def arcclose(self):
        """Close all handles and clear cache."""
        self.handle.clear()
        self.embedded_files.clear()
        self.filename_to_index.clear()

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect OneNote format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or empty dict if not recognized
        """
        ret = {}

        try:
            mm = filehandle
            if is_onenote(mm):
                ret["ff_onenote"] = "OneNote"

                if self.verbose:
                    print("-" * 79)
                    print("OneNote File Format")
                    print("-" * 79)
        except Exception as e:
            logger.error("Error analyzing OneNote format: %s", e)

        return ret

    def arclist(self, filename, fileformat, password=None):
        """Get list of embedded files in OneNote.

        Args:
            filename: Path to OneNote file
            fileformat: Format info from format() method
            password: Optional password (not used for OneNote)

        Returns:
            List of tuples: (engine_id, embedded_filename)
        """
        file_scan_list = []

        if "ff_onenote" not in fileformat:
            return file_scan_list

        try:
            with open(filename, "rb") as f:
                data = f.read()

            # Extract embedded files (with original filenames)
            embedded = extract_embedded_files(data, include_filenames=True)

            # Store in cache for later extraction
            self.handle[filename] = data
            self.embedded_files[filename] = embedded

            # Track used names to avoid duplicates
            used_names = set()

            # Build file list
            for i, ef in enumerate(embedded):
                # Get original filename or generate one from signature
                original_name = ef.get("original_filename")
                ext = get_extension_from_signature(ef["data"])

                if original_name:
                    # Use original filename, but ensure uniqueness
                    embedded_name = original_name
                    if embedded_name in used_names:
                        # Add index to make unique
                        base, file_ext = (
                            (original_name.rsplit(".", 1)[0], "." + original_name.rsplit(".", 1)[1])
                            if "." in original_name
                            else (original_name, "")
                        )
                        embedded_name = f"{base}_{i}{file_ext}"
                else:
                    # Fall back to signature-based name
                    embedded_name = f"embedded_{i}{ext}"

                used_names.add(embedded_name)
                file_scan_list.append(("arc_onenote", embedded_name))

                # Store filename to index mapping for unarc()
                if filename not in self.filename_to_index:
                    self.filename_to_index[filename] = {}
                self.filename_to_index[filename][embedded_name] = i

                if self.verbose:
                    orig_info = f" (original: {original_name})" if original_name else ""
                    print(f"  [{i}] {embedded_name} ({ef['size']} bytes){orig_info}")

        except IOError as e:
            logger.error("Error reading OneNote file %s: %s", filename, e)
        except Exception as e:
            logger.error("Error listing OneNote contents: %s", e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract embedded file from OneNote.

        Args:
            arc_engine_id: Archive engine ID (must be 'arc_onenote')
            arc_name: Path to OneNote file
            fname_in_arc: Embedded filename to extract

        Returns:
            Extracted file data, or None on error
        """
        if arc_engine_id != "arc_onenote":
            return None

        # Security check for path traversal
        if not k2security.is_safe_archive_member(fname_in_arc):
            logger.warning("Unsafe archive member name: %s", fname_in_arc)
            return None

        try:
            # Check if we have cached data
            if arc_name not in self.embedded_files:
                return None

            embedded = self.embedded_files[arc_name]

            # Try to get index from filename mapping first
            index = None
            if arc_name in self.filename_to_index:
                index = self.filename_to_index[arc_name].get(fname_in_arc)

            # Fall back to parsing "embedded_X.ext" format
            if index is None:
                try:
                    base_name = fname_in_arc.rsplit(".", 1)[0]  # Remove extension
                    if base_name.startswith("embedded_"):
                        index = int(base_name.split("_")[1])
                except (ValueError, IndexError):
                    pass

            if index is None:
                logger.warning("Cannot resolve filename to index: %s", fname_in_arc)
                return None

            if 0 <= index < len(embedded):
                return embedded[index]["data"]

        except Exception as e:
            logger.error("Error extracting from OneNote: %s", e)

        return None
