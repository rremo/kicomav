# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
GZ Archive Engine Plugin

This plugin handles GZIP archive format for scanning and manipulation.
"""

import gzip
import struct
from typing import Optional

from kicomav.plugins import kernel
from kicomav.kavcore.k2plugin_base import SingleStreamArchiveBase


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(SingleStreamArchiveBase):
    """GZ archive handler plugin.

    This plugin provides functionality for:
    - Detecting GZIP archive format
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives
    """

    # Set engine type to ARCHIVE_ENGINE
    engine_type = kernel.ARCHIVE_ENGINE
    # SingleStreamArchiveBase configuration
    format_key = "ff_gz"
    engine_id = "arc_gz"
    signature = b"\x1f\x8b"  # GZIP magic number
    signature_offset = 0

    def __init__(self):
        """Initialize the GZ plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.2",
            title="GZ Archive Engine",
            kmd_name="gz",
        )

    def _open_stream(self, filename: str, mode: str):
        """Open GZIP stream.

        Args:
            filename: Path to archive file
            mode: Open mode ("rb" for read, "wb" for write)

        Returns:
            gzip file object (context manager)
        """
        return gzip.open(filename, mode)

    def _detect_format(self, filehandle: bytes, filename: str) -> Optional[str]:
        """Detect GZIP format and extract original filename from header.

        GZIP header structure:
        - Bytes 0-1: Magic number (0x1F, 0x8B)
        - Byte 2: Compression method (8 = deflate)
        - Byte 3: Flags (bit 3 = FNAME present)
        - Bytes 4-7: Modification time
        - Byte 8: Extra flags
        - Byte 9: OS
        - If FEXTRA (bit 2): 2-byte length + extra data
        - If FNAME (bit 3): Null-terminated original filename

        Args:
            filehandle: File data
            filename: Original filename

        Returns:
            Inner filename or None if not recognized
        """
        if len(filehandle) < 10:
            return None

        header = filehandle[:10]
        try:
            id1, id2, cm, flg, mtime, xfl, os_ = struct.unpack("<BBBBIBB", header)
        except struct.error:
            return None

        # Check GZIP magic number
        if id1 != 0x1F or id2 != 0x8B:
            return None

        pos = 10

        # Skip FEXTRA field if present
        if flg & 0x04:
            if len(filehandle) < 12:
                return "GZ"
            xlen = struct.unpack("<H", filehandle[10:12])[0]
            pos = 12 + xlen

        # Extract FNAME (original filename) if present
        if flg & 0x08:
            name_bytes = bytearray()
            while pos < len(filehandle):
                b = filehandle[pos]
                pos += 1
                if b == 0:
                    break
                name_bytes.append(b)
            if name_bytes:
                return name_bytes.decode("utf-8", errors="ignore")

        # No FNAME field, use default naming
        return "GZ"
