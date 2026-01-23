# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
BZ2 Archive Engine Plugin

This plugin handles BZ2 archive format for scanning and manipulation.
Includes support for detecting attached data after BZ2 stream.
"""

import bz2
import mmap
from typing import Any, Dict, List, Optional

from kicomav.plugins import kernel
from kicomav.kavcore.k2plugin_base import SingleStreamArchiveBase


# -------------------------------------------------------------------------
# class BZ2File
# -------------------------------------------------------------------------
class BZ2File:
    """BZ2 file handler with attached data support.

    This class handles BZ2 files that may have additional data
    appended after the compressed stream (attached data).
    """

    def __init__(self, filename: str, mode: str = "r"):
        """Initialize BZ2File handler.

        Args:
            filename: Path to BZ2 file
            mode: Open mode ('r' for read, 'w' for write)
        """
        self.mode = mode
        self.decompress_data = None
        self.unused_data = None
        self.fp = None
        self.mm = None
        self.bz2_file = None

        if mode == "r":
            self.fp = open(filename, "rb")
            self.mm = mmap.mmap(self.fp.fileno(), 0, access=mmap.ACCESS_READ)
        else:  # mode == 'w'
            self.bz2_file = bz2.BZ2File(filename, "w")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def is_bz2(self) -> bool:
        """Check if file has BZ2 signature."""
        return self.mode == "r" and self.mm[:3] == b"BZh"

    def is_attach(self) -> bool:
        """Check if file has attached data after BZ2 stream."""
        if self.mode != "r":
            return False

        if not self.decompress_data:
            self.read()

        return bool(self.unused_data)

    def read(self) -> Optional[bytes]:
        """Read and decompress BZ2 data.

        Handles concatenated BZ2 streams and detects attached data.

        Returns:
            Decompressed data, or None if not valid BZ2
        """
        if self.mode != "r":
            return None

        if not self.is_bz2():
            return None

        if self.decompress_data:
            return self.decompress_data

        data = b""
        src = self.mm[:]

        while src:
            try:
                decompressor = bz2.BZ2Decompressor()
                data += decompressor.decompress(src)
                src = decompressor.unused_data
            except IOError:
                break

        if src:
            self.unused_data = src

        if data:
            self.decompress_data = data
            return self.decompress_data

        return None

    def get_attach_info(self) -> tuple:
        """Get attached data information.

        Returns:
            Tuple of (offset, size) or (None, None) if no attached data
        """
        if self.mode != "r":
            return None, None

        if not self.decompress_data:
            self.read()

        if self.unused_data:
            asize = len(self.unused_data)
            return len(self.mm) - asize, asize

        return None, None

    def write(self, data: bytes) -> bool:
        """Write compressed data.

        Args:
            data: Data to compress and write

        Returns:
            True if successful
        """
        if self.mode != "w" or not self.bz2_file:
            return False

        self.bz2_file.write(data)
        return True

    def close(self):
        """Close file handles."""
        if self.mm:
            self.mm.close()
            self.mm = None
        if self.fp:
            self.fp.close()
            self.fp = None
        if self.bz2_file:
            self.bz2_file.close()
            self.bz2_file = None

    def __del__(self):
        self.close()


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(SingleStreamArchiveBase):
    """BZ2 archive handler plugin.

    This plugin provides functionality for:
    - Detecting BZ2 archive format
    - Listing files within archives
    - Extracting files from archives
    - Creating/updating archives
    - Detecting attached data after BZ2 stream
    """

    # Set engine type to ARCHIVE_ENGINE
    engine_type = kernel.ARCHIVE_ENGINE
    # SingleStreamArchiveBase configuration
    format_key = "ff_bz2"
    engine_id = "arc_bz2"
    signature = b"BZh"  # BZ2 magic number
    signature_offset = 0

    def __init__(self):
        """Initialize the BZ2 plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.2",
            title="Bz2 Archive Engine",
            kmd_name="bz2",
        )

    def _open_stream(self, filename: str, mode: str):
        """Open BZ2 stream using custom BZ2File handler.

        Args:
            filename: Path to archive file
            mode: Open mode ("r" for read, "w" for write)

        Returns:
            BZ2File object (context manager)
        """
        # Map "rb"/"wb" to "r"/"w" for BZ2File
        bz2_mode = "r" if mode.startswith("r") else "w"
        return BZ2File(filename, bz2_mode)

    def __get_handle(self, filename: str) -> BZ2File:
        """Get or create cached handle for BZ2 file."""
        return self._get_or_create_handle(filename, BZ2File)

    def format(self, filehandle: bytes, filename: str, filename_ex: str) -> Optional[Dict[str, Any]]:
        """Analyze and detect BZ2 format with attached data detection.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info including attached data, or None
        """
        try:
            if filehandle[:3] != self.signature:
                return None

            fileformat = {}

            with BZ2File(filename) as bfile:
                aoff, asize = bfile.get_attach_info()
                fileformat[self.format_key] = "BZ2"

                if aoff:
                    fileformat["ff_attach"] = {
                        "Attached_Pos": aoff,
                        "Attached_Size": asize,
                    }

                return fileformat

        except (IOError, OSError) as e:
            self.logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return None

    def unarc(self, arc_engine_id: str, arc_name: str, fname_in_arc: str) -> Optional[bytes]:
        """Extract the compressed content using cached handles.

        Args:
            arc_engine_id: Engine ID (must be 'arc_bz2')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract (ignored for single-stream)

        Returns:
            Decompressed file data, or None on error
        """
        if arc_engine_id != self.engine_id:
            return None

        try:
            bfile = self.__get_handle(arc_name)
            return bfile.read()

        except (IOError, OSError) as e:
            self.logger.debug("Archive extract IO error for %s: %s", arc_name, e)
        except Exception as e:
            self.logger.warning("Unexpected error extracting from %s: %s", arc_name, e)

        return None

    def mkarc(self, arc_engine_id: str, arc_name: str, file_infos: List[Any]) -> bool:
        """Create a BZ2 archive using custom BZ2File handler.

        Args:
            arc_engine_id: Engine ID (must be 'arc_bz2')
            arc_name: Path for new archive
            file_infos: List of file info (only first is used)

        Returns:
            True if successful, False otherwise
        """
        if arc_engine_id != self.engine_id:
            return False

        if not file_infos:
            return False

        try:
            file_info = file_infos[0]
            source_name = file_info.get_filename()

            with open(source_name, "rb") as fp:
                data = fp.read()

            bfile = BZ2File(arc_name, "w")
            bfile.write(data)
            bfile.close()
            return True

        except (IOError, OSError) as e:
            self.logger.error("Archive creation IO error for %s: %s", arc_name, e)
        except Exception as e:
            self.logger.error("Unexpected error creating archive %s: %s", arc_name, e)

        return False
