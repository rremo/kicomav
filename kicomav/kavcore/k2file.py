# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV File Utilities

This module provides file handling utilities including temporary file management
and file structure tracking for archive scanning.
"""

import contextlib
import os
import re
import secrets
import shutil
import tempfile
from typing import Optional, Dict, Any, Pattern


# ---------------------------------------------------------------------
# K2Tempfile Class
# ---------------------------------------------------------------------
class K2Tempfile:
    """Secure temporary file management for KicomAV."""

    def __init__(self) -> None:
        # CWE-377: Use cryptographically secure random name instead of PID
        self.re_pid: Pattern[str] = re.compile(r"ktmp([0-9a-f]{16})$", re.IGNORECASE)
        random_suffix = secrets.token_hex(8)  # 16 hex chars
        self.temp_path: str = os.path.join(tempfile.gettempdir(), f"ktmp{random_suffix}")

        if not os.path.exists(self.temp_path):
            try:
                os.mkdir(self.temp_path)
            except (IOError, OSError):
                self.temp_path = tempfile.gettempdir()

    def gettempdir(self) -> str:
        """Get the temporary directory path."""
        return self.temp_path

    def mktemp(self) -> str:
        """
        Create a secure temporary file and return its path.
        Uses mkstemp instead of mktemp to prevent race condition (CWE-377).
        """
        fd, path = tempfile.mkstemp(prefix="ktmp", dir=self.temp_path)
        os.close(fd)  # Close file descriptor, file remains
        return path

    def removetempdir(self) -> None:
        """Delete the temporary directory and its contents."""
        with contextlib.suppress(OSError):
            if os.path.exists(self.temp_path):
                shutil.rmtree(self.temp_path)


# -------------------------------------------------------------------------
# FileStruct Class
# -------------------------------------------------------------------------
class FileStruct:
    """File structure tracking for archive scanning operations."""

    # ---------------------------------------------------------------------
    # __init__(self, filename=None)
    # Initialize the class
    # Argument: filename - File name
    # ---------------------------------------------------------------------
    def __init__(self, filename: Optional[str] = None, level: int = 0) -> None:
        self.__fs: Dict[str, Any] = {}

        if filename:
            self.set_default(filename, level)

    # ---------------------------------------------------------------------
    # set_default(self, filename)
    # Create a FileStruct for a file
    # Argument: filename - File name
    # ---------------------------------------------------------------------
    def set_default(self, filename: str, level: int) -> None:
        from kicomav.plugins import kernel

        self.__fs["is_arc"] = False  # Compression status
        self.__fs["arc_engine_name"] = None  # Decompression engine ID
        self.__fs["arc_filename"] = ""  # Actual compressed file
        self.__fs["filename_in_arc"] = ""  # Decompression target file
        self.__fs["real_filename"] = filename  # Inspection target file
        self.__fs["additional_filename"] = ""  # File name for internal representation of compressed file
        self.__fs["master_filename"] = filename  # Output
        self.__fs["is_modify"] = False  # Modify status
        self.__fs["can_arc"] = kernel.MASTER_IGNORE  # Recompression possible status
        self.__fs["level"] = level  # Compression depth

    # ---------------------------------------------------------------------
    # is_archive(self)
    # Check the compression status of the file
    # Return: True or False
    # ---------------------------------------------------------------------
    def is_archive(self) -> bool:
        """Check if the file is an archive."""
        return self.__fs["is_arc"]

    # ---------------------------------------------------------------------
    # get_archive_engine_name(self)
    # Check the decompression engine
    # Return: Decompression engine (ex, arc_zip)
    # ---------------------------------------------------------------------
    def get_archive_engine_name(self) -> Optional[str]:
        """Get the archive engine name."""
        return self.__fs["arc_engine_name"]

    # ---------------------------------------------------------------------
    # get_archive_filename(self)
    # Check the actual compressed file name
    # Return: Actual compressed file name
    # ---------------------------------------------------------------------
    def get_archive_filename(self) -> str:
        """Get the archive filename."""
        return self.__fs["arc_filename"]

    # ---------------------------------------------------------------------
    # get_filename_in_archive(self)
    # Check the decompression target file name
    # Return: Decompression target file
    # ---------------------------------------------------------------------
    def get_filename_in_archive(self) -> str:
        """Get the filename within the archive."""
        return self.__fs["filename_in_arc"]

    # ---------------------------------------------------------------------
    # get_filename(self)
    # Check the actual working target file name
    # Return: Actual working target file
    # ---------------------------------------------------------------------
    def get_filename(self) -> str:
        """Get the actual working filename."""
        return self.__fs["real_filename"]

    # ---------------------------------------------------------------------
    # set_filename(self)
    # Save the actual working target file name
    # Argument: Actual working target file
    # ---------------------------------------------------------------------
    def set_filename(self, fname: str) -> None:
        """Set the actual working filename."""
        self.__fs["real_filename"] = fname

    # ---------------------------------------------------------------------
    # get_master_filename(self)
    # Check the top file name
    # Return: Compressed file name
    # ---------------------------------------------------------------------
    def get_master_filename(self) -> str:
        """Get the master (top-level) filename."""
        return self.__fs["master_filename"]

    # ---------------------------------------------------------------------
    # get_additional_filename(self)
    # Check the file name for representing the compressed file
    # Return: File name for representing the compressed file
    # ---------------------------------------------------------------------
    def get_additional_filename(self) -> str:
        """Get the additional filename for display."""
        return self.__fs["additional_filename"]

    # ---------------------------------------------------------------------
    # set_additional_filename(self, filename)
    # Set the file name for representing the compressed file
    # ---------------------------------------------------------------------
    def set_additional_filename(self, filename: str) -> None:
        """Set the additional filename for display."""
        self.__fs["additional_filename"] = filename

    # ---------------------------------------------------------------------
    # is_modify(self)
    # Check if the file has been modified due to virus removal
    # Return: True or False
    # ---------------------------------------------------------------------
    def is_modify(self) -> bool:
        """Check if the file has been modified."""
        return self.__fs["is_modify"]

    # ---------------------------------------------------------------------
    # set_modify(self, modify)
    # Save the modification status due to virus removal
    # Argument: Modify status (True or False)
    # ---------------------------------------------------------------------
    def set_modify(self, modify: bool) -> None:
        """Set the modification status."""
        self.__fs["is_modify"] = modify

    # ---------------------------------------------------------------------
    # get_can_archive(self)
    # Check if the file can be recompressed after virus removal
    # Return: kernel.MASTER_IGNORE, kernel.MASTER_PACK, kernel.MASTER_DELETE
    # ---------------------------------------------------------------------
    def get_can_archive(self) -> int:
        """Get the recompression capability status."""
        return self.__fs["can_arc"]

    # ---------------------------------------------------------------------
    # set_can_archive(self, mode)
    # Set if the file can be recompressed after virus removal
    # Argument: mode - kernel.MASTER_IGNORE, kernel.MASTER_PACK, kernel.MASTER_DELETE
    # ---------------------------------------------------------------------
    def set_can_archive(self, mode: int) -> None:
        """Set the recompression capability status."""
        self.__fs["can_arc"] = mode

    # ---------------------------------------------------------------------
    # get_level(self)
    # Check the compression depth
    # Return: 0, 1, 2 ...
    # ---------------------------------------------------------------------
    def get_level(self) -> int:
        """Get the compression depth level."""
        return self.__fs["level"]

    # ---------------------------------------------------------------------
    # set_level(self, level)
    # Set the compression depth
    # Argument: level - Compression depth
    # ---------------------------------------------------------------------
    def set_level(self, level: int) -> None:
        """Set the compression depth level."""
        self.__fs["level"] = level

    # ---------------------------------------------------------------------
    # set_archive(self, engine_id, rname, fname, dname, mname, modify, can_arc)
    # Save the file information given the information
    # Argument: engine_id - Decompression possible engine ID
    #           rname     - Compressed file
    #           fname     - Decompression target file
    #           dname     - File name for representing the compressed file
    #           mname     - Master file (Top file name)
    #           modify    - Modify status
    #           can_arc   - Recompression possible status
    #           level     - Compression depth
    # ---------------------------------------------------------------------
    def set_archive(
        self,
        engine_id: str,
        rname: str,
        fname: str,
        dname: str,
        mname: str,
        modify: bool,
        can_arc: int,
        level: int,
    ) -> None:
        """Set archive information for the file structure."""
        self.__fs["is_arc"] = True  # Compression status
        self.__fs["arc_engine_name"] = engine_id  # Decompression possible engine ID
        self.__fs["arc_filename"] = rname  # Actual compressed file
        self.__fs["filename_in_arc"] = fname  # Decompression target file
        self.__fs["real_filename"] = ""  # Inspection target file
        self.__fs["additional_filename"] = dname  # File name for representing the compressed file
        self.__fs["master_filename"] = mname  # Master file (Top file name)
        self.__fs["is_modify"] = modify  # Modify status
        self.__fs["can_arc"] = can_arc  # Recompression possible status
        self.__fs["level"] = level  # Compression depth
