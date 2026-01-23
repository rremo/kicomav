# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
CArchive Archive Engine Plugin

This plugin handles CArchive (PyInstaller) format for scanning and manipulation.
"""

import contextlib
import logging
import mmap
import struct
import zlib

from kicomav.kavcore import k2security
from kicomav.kavcore.k2plugin_base import ArchivePluginBase

logger = logging.getLogger(__name__)

# https://github.com/kennethreitz-archive/pyinstaller/blob/master/carchive.py
MAGIC = b"MEI\x0C\x0B\x0A\x0B\x0E"  # == b"MEI\014\013\012\013\016"


class CArchiveFile:
    """CArchive file handler."""

    def __init__(self, filename, verbose=False):
        self.verbose = verbose
        self.filename = filename
        self.fp = None
        self.mm = None
        self.tocs = {}

        self.parse()

    def parse(self):
        try:
            fp = open(self.filename, "rb")
            mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)

            self.fp = fp
            self.mm = mm

            mpos = mm[-4096:].rfind(MAGIC)
            mbuf = mm[-4096 + mpos :]

            magic, totallen, tocpos, toclen, pyvers, pylib_name = struct.unpack("!8siiii64s", mbuf[:88])
            if magic == MAGIC:
                logger.debug(
                    "CArchive totallen: %d, tocpos: %d, toclen: %d, pyvers: %d, pylib_name: %s",
                    totallen,
                    tocpos,
                    toclen,
                    pyvers,
                    pylib_name,
                )

                pkg_start = len(mm) - totallen
                logger.debug("CArchive pkg_start: %d, len(mm): %d, totallen: %d", pkg_start, len(mm), totallen)

                s = mm[pkg_start + tocpos : pkg_start + tocpos + toclen]
                p = 0

                # Detect TOC entry format: new (4-byte slen) vs old (2-byte slen)
                # Try new format first, if slen is unreasonable, use old format
                use_old_format = False
                if len(s) >= 18:
                    test_slen = struct.unpack("!i", s[:4])[0]
                    # If slen is too large or negative, try old format
                    if test_slen <= 0 or test_slen > 1000:
                        use_old_format = True
                        logger.debug("CArchive using old TOC format (2-byte slen)")

                while p < toclen:
                    if use_old_format:
                        # Old format: 2-byte slen (PyInstaller for Python 2.x)
                        if p + 16 > toclen:
                            break
                        slen, dpos, dlen, ulen, flag, typcd = struct.unpack("!HiiiBB", s[p : p + 16])
                        header_size = 16
                    else:
                        # New format: 4-byte slen (PyInstaller for Python 3.x)
                        if p + 18 > toclen:
                            break
                        slen, dpos, dlen, ulen, flag, typcd = struct.unpack("!iiiiBB", s[p : p + 18])
                        header_size = 18

                    logger.debug(
                        "CArchive slen: %d, dpos: %d, dlen: %d, ulen: %d, flag: %d, typcd: %s",
                        slen,
                        dpos,
                        dlen,
                        ulen,
                        flag,
                        chr(typcd),
                    )

                    if slen <= header_size or slen > 1000:
                        logger.debug("CArchive invalid slen %d at position %d", slen, p)
                        break

                    nmlen = slen - header_size
                    p += header_size
                    (nm,) = struct.unpack("%is" % nmlen, s[p : p + nmlen])
                    p += nmlen
                    nm = nm.rstrip(b"\0")
                    nm = nm.decode("utf-8")

                    # Add .pyc extension for module(m) and script(s) types
                    typcd_chr = chr(typcd)
                    if typcd_chr in ("m", "s"):
                        nm = nm + ".pyc"

                    logger.debug("CArchive nm: %s", nm)

                    self.tocs[nm] = {
                        "Data Pos": dpos,
                        "Data Length": dlen,
                        "Flag": flag,
                    }
        except struct.error as e:
            logger.debug("CArchive parse struct error for %s: %s", self.filename, e)
        except IOError as e:
            logger.debug("CArchive parse IO error for %s: %s", self.filename, e)

    def close(self):
        if self.mm:
            self.mm.close()
            self.mm = None

        if self.fp:
            self.fp.close()
            self.fp = None

    def namelist(self):
        return self.tocs.keys() if len(self.tocs) else []

    def read(self, fname):
        with contextlib.suppress(KeyError, zlib.error, k2security.DecompressionBombError):
            toc = self.tocs[fname]
            start = toc["Data Pos"]
            size = toc["Data Length"]
            flag = toc["Flag"]

            data = self.mm[start : start + size]

            if flag:
                # Use safe decompression to prevent bomb attacks
                data = k2security.safe_zlib_decompress(data)

            return data

        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """CArchive archive handler plugin.

    This plugin provides functionality for:
    - Detecting CArchive (PyInstaller) format
    - Listing files within archives
    - Extracting files from archives
    """

    def __init__(self):
        """Initialize the CArchive plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="CArchive Engine",
            kmd_name="carch",
        )

    def __get_handle(self, filename):
        """Get or create handle for CArchive file."""
        return self._get_or_create_handle(filename, CArchiveFile, self.verbose)

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect CArchive format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to archive file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or None if not recognized
        """
        try:
            mm = filehandle

            # CArchive (PyInstaller) has MEI Magic near the end of the file
            # Check when extracted from ELF/PE as "CArchive" or "Attached"
            if filename_ex.find("CArchive") != -1 or filename_ex.find("Attached") != -1:
                buf = mm[-4096:]
                if buf.rfind(MAGIC) != -1:
                    return {"ff_carch": "CArchive"}

        except (IOError, OSError) as e:
            self.logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return None

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive.

        Args:
            filename: Path to archive file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_carch" not in fileformat:
            return file_scan_list

        try:
            zfile = self.__get_handle(filename)
            if zfile is None:
                return file_scan_list

            for name in zfile.namelist():
                # CWE-22: Path traversal prevention
                if k2security.is_safe_archive_member(name):
                    file_scan_list.append(["arc_carch", name])

        except (IOError, OSError) as e:
            self.logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_carch')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            self.logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_carch":
            return None

        try:
            zfile = self.__get_handle(arc_name)
            if zfile is None:
                return None

            return zfile.read(fname_in_arc)

        except (IOError, OSError) as e:
            self.logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except Exception as e:
            self.logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None
