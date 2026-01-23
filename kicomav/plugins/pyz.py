# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
PYZ Archive Engine Plugin

This plugin handles PYZ (Python Zip) format for scanning and manipulation.
"""

import contextlib
import logging
import os
import re
import struct
import time
import zlib

from kicomav.plugins import cryptolib
from kicomav.plugins import kavutil
from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.k2plugin_base import ArchivePluginBase

logger = logging.getLogger(__name__)

# https://github.com/nedbat/coveragepy/blob/master/lab/show_pyc.py


class PyzFile:
    def __init__(self, filename, verbose=False):
        self.verbose = verbose  # for debugging
        self.filename = filename
        self.fp = None
        self.tocs = None
        self.parse()

    def parse(self):
        with contextlib.suppress(IOError):
            self.fp = open(self.filename, "rb")
            fp = self.fp
            magic = fp.read(4)

            if magic != b"PYZ\x00":  # Check the header
                fp.close()
                self.fp = None
                return None

            fp.seek(8)
            toc_off = struct.unpack(">L", fp.read(4))[0]  # TOC position in PKZ file

            fp.seek(toc_off)
            toc = fp.read()
            # Use secure marshal loading with type validation (CWE-502)
            try:
                self.tocs = k2security.safe_marshal_load_toc(toc)
            except k2security.MarshalSecurityError as e:
                logger.warning("Security issue in PYZ file %s: %s", self.filename, e)
                fp.close()
                self.fp = None
                return None

    def close(self):
        if self.fp:
            self.fp.close()
            self.fp = None

    def namelist(self):
        names = []

        if self.tocs:
            if isinstance(self.tocs, dict):
                for key in self.tocs.keys():
                    if isinstance(key, bytes):
                        name = key.decode("utf-8", "replace")
                    else:
                        name = key
                    names.append(name + ".pyc")
            elif isinstance(self.tocs, list):
                for x in self.tocs:
                    name = x[0]
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", "replace")
                    names.append(name + ".pyc")

        return names

    def read(self, fname):
        # Remove .pyc extension if present for lookup
        if isinstance(fname, str) and fname.endswith(".pyc"):
            fname = fname[:-4]
        elif isinstance(fname, bytes) and fname.endswith(b".pyc"):
            fname = fname[:-4]

        # Try both string and bytes versions of fname for lookup
        fname_bytes = fname.encode("utf-8") if isinstance(fname, str) else fname
        fname_str = fname if isinstance(fname, str) else fname.decode("utf-8", "replace")

        with contextlib.suppress(KeyError):
            start = None
            size = None
            flag = False

            if isinstance(self.tocs, dict):
                # Try string key first, then bytes key
                if fname_str in self.tocs:
                    toc = self.tocs[fname_str]
                elif fname_bytes in self.tocs:
                    toc = self.tocs[fname_bytes]
                else:
                    return None
                start = toc[1]
                size = toc[2]
                flag = True
            elif isinstance(self.tocs, list):
                for x in self.tocs:
                    key = x[0]
                    # Compare with both string and bytes versions
                    if key == fname_str or key == fname_bytes:
                        start = x[1][1]
                        size = x[1][2]
                        flag = True
                        break

            if start is not None:
                self.fp.seek(start)
                data = self.fp.read(size)

                if flag:
                    data = zlib.decompress(data)

                return data

        return None


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """PYZ archive handler plugin.

    This plugin provides functionality for:
    - Detecting PYZ (Python Zip) format
    - Detecting PYC (Python compiled) format
    - Listing files within PYZ archives
    - Extracting files from PYZ archives
    - Scanning for malware in PYC files
    """

    def __init__(self):
        """Initialize the PYZ plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="PYZ Engine",
            kmd_name="pyz",
        )
        self.p_string = None

    def _custom_init(self) -> int:
        """Custom initialization for PYZ plugin.

        Returns:
            0 for success
        """
        chars = rb"A-Za-z0-9/\-=:.,_$%@'()[\]<> "
        shortest_run = 5
        regexp = b"[%s]{%d,}" % (chars, shortest_run)
        self.p_string = re.compile(regexp)
        return 0

    def __get_handle(self, filename):
        """Get or create handle for PYZ file."""
        return self._get_or_create_handle(filename, PyzFile, self.verbose)

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect PYZ/PYC format.

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

            # https://github.com/nedbat/coveragepy/blob/master/lab/show_pyc.py
            # Python 2.7: [magic_num][source_modified_time]
            # Python >= 3.2 (PEP-3147): [magic_num][source_modified_time][source_size]
            # Python >= 3.8 (PEP-0552): [magic_num][bit-field][source_modified_time][source_size]

            if mm[:4] == b"PYZ\x00":
                ret["ff_pyz"] = "PYZ"
            elif mm[2:4] == b"\x0d\x0a":
                with contextlib.suppress(Exception):
                    modtime1 = time.localtime(struct.unpack("<L", mm[4:8])[0])
                    modtime2 = time.localtime(struct.unpack("<L", mm[8:12])[0])

                    if 2010 <= modtime1.tm_year <= time.localtime().tm_year:
                        ret["ff_pyc"] = "Python < 3.8"
                    elif 2010 <= modtime2.tm_year <= time.localtime().tm_year:
                        ret["ff_pyc"] = "Python >= 3.8"

        except (IOError, OSError) as e:
            self.logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return ret

    def arclist(self, filename, fileformat, password=None):
        """List files in the archive.

        Args:
            filename: Path to archive file
            fileformat: Format info from format() method

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        if "ff_pyz" not in fileformat:
            return file_scan_list

        try:
            zfile = self.__get_handle(filename)
            if zfile is None:
                return file_scan_list

            for name in zfile.namelist():
                # CWE-22: Path traversal prevention
                if k2security.is_safe_archive_member(name):
                    file_scan_list.append(["arc_pyz", name])

        except (IOError, OSError) as e:
            self.logger.debug("Archive list IO error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error listing archive %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract a file from the archive.

        Args:
            arc_engine_id: Engine ID ('arc_pyz')
            arc_name: Path to archive file
            fname_in_arc: Name of file to extract

        Returns:
            Extracted file data, or None on error
        """
        # CWE-22: Path traversal prevention
        if not k2security.is_safe_archive_member(fname_in_arc):
            self.logger.warning("Unsafe archive member rejected: %s in %s", fname_in_arc, arc_name)
            return None

        if arc_engine_id != "arc_pyz":
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

    def scan(self, filehandle, filename, fileformat, filename_ex):
        """Scan for malware.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            fileformat: Format info from format() method
            filename_ex: Extended filename info

        Returns:
            Tuple of (found, malware_name, malware_id, result)
        """
        try:
            if "ff_pyc" not in fileformat:
                return False, "", -1, kernel.NOT_FOUND

            if self.verbose:
                self.logger.info("-" * 79)
                kavutil.vprint("Engine")
                kavutil.vprint(None, "Engine", "pyz")

            mm = filehandle

            if len(mm):
                if self.verbose:
                    kavutil.vprint("String")

                for match in self.p_string.finditer(mm):
                    find_str = match.group()
                    find_str_off = match.start()

                    x = kavutil.get_uint32(mm, find_str_off - 4)
                    if len(find_str) < x:
                        continue

                    buf = find_str[:x]
                    fsize = len(buf)

                    if self.verbose:
                        fmd5 = cryptolib.md5(buf)
                        kavutil.vprint(None, fmd5, "%3d : %s" % (fsize, buf))

                    if fsize and kavutil.handle_pattern_md5.match_size("emalware", fsize):
                        fmd5 = cryptolib.md5(buf)
                        if vname := kavutil.handle_pattern_md5.scan("emalware", fsize, fmd5):
                            return True, vname, kernel.DISINFECT_DELETE, kernel.INFECTED

        except (IOError, OSError) as e:
            self.logger.debug("Scan IO error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error scanning %s: %s", filename, e)

        return False, "", -1, kernel.NOT_FOUND

    def disinfect(self, filename, malware_id):
        """Disinfect malware.

        Args:
            filename: Path to infected file
            malware_id: Malware ID to disinfect

        Returns:
            True if successful, False otherwise
        """
        try:
            if malware_id == kernel.DISINFECT_DELETE:
                # CWE-73: Safe file deletion
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True

        except (IOError, OSError, k2security.SecurityError) as e:
            self.logger.debug("Disinfect error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error disinfecting %s: %s", filename, e)

        return False
