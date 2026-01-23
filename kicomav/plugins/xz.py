# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
XZ Archive Engine Plugin

This plugin handles XZ/LZMA archive format for scanning and manipulation.
"""

import lzma
from typing import Optional

from kicomav.plugins import kernel
from kicomav.kavcore.k2plugin_base import SingleStreamArchiveBase


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(SingleStreamArchiveBase):
    """XZ archive handler plugin.

    This plugin provides functionality for:
    - Detecting XZ archive format
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives
    """

    # Set engine type to ARCHIVE_ENGINE
    engine_type = kernel.ARCHIVE_ENGINE
    # SingleStreamArchiveBase configuration
    format_key = "ff_xz"
    engine_id = "arc_xz"
    signature = b"\xFD7zXZ\x00"  # XZ magic number
    signature_offset = 0

    def __init__(self):
        """Initialize the XZ plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.2",
            title="XZ Archive Engine",
            kmd_name="xz",
        )

    def _open_stream(self, filename: str, mode: str):
        """Open XZ/LZMA stream.

        Args:
            filename: Path to archive file
            mode: Open mode ("rb" for read, "wb" for write)

        Returns:
            lzma file object (context manager)
        """
        return lzma.open(filename, mode)

    def _detect_format(self, filehandle: bytes, filename: str) -> Optional[str]:
        """Detect XZ format by checking signature.

        Args:
            filehandle: File data
            filename: Original filename (not used)

        Returns:
            "XZ" if valid XZ format, None otherwise
        """
        if len(filehandle) >= 6 and filehandle[:6] == self.signature:
            return "XZ"
        return None
