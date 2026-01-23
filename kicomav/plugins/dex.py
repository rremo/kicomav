# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
DEX (Dalvik Executable) Scan Engine Plugin

This plugin detects Android malware by parsing DEX files and scanning
extracted strings, class names, and method names using YARA rules.
"""

import struct
import os

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.k2plugin_base import MalwareDetectorBase
from kicomav.kavcore.k2yara import YaraRuleLoader


# -------------------------------------------------------------------------
# DEX Constants
# -------------------------------------------------------------------------
DEX_MAGIC = b"dex\n"
DEX_HEADER_SIZE = 112


# -------------------------------------------------------------------------
# DEX Parser Class
# -------------------------------------------------------------------------
class DexParser:
    """Parser for DEX (Dalvik Executable) file format."""

    def __init__(self, data: bytes):
        """Initialize DEX parser with file data.

        Args:
            data: Raw bytes of DEX file
        """
        self.data = data
        self.strings = []
        self.classes = []
        self.methods = []
        self.is_valid = False

        if self._validate_header():
            self._parse()

    def _validate_header(self) -> bool:
        """Validate DEX file header.

        Returns:
            True if valid DEX file, False otherwise
        """
        if len(self.data) < DEX_HEADER_SIZE:
            return False

        if not self.data[:4] == DEX_MAGIC:
            return False

        self.is_valid = True
        return True

    def _read_uleb128(self, offset: int) -> tuple[int, int]:
        """Read unsigned LEB128 encoded integer.

        Args:
            offset: Starting offset in data

        Returns:
            Tuple of (value, new_offset)
        """
        result = 0
        shift = 0
        while offset < len(self.data):
            byte = self.data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, offset

    def _parse(self) -> None:
        """Parse DEX file and extract strings, classes, and methods."""
        try:
            # Parse header offsets
            string_ids_size = struct.unpack("<I", self.data[56:60])[0]
            string_ids_off = struct.unpack("<I", self.data[60:64])[0]
            type_ids_size = struct.unpack("<I", self.data[64:68])[0]
            type_ids_off = struct.unpack("<I", self.data[68:72])[0]
            method_ids_size = struct.unpack("<I", self.data[88:92])[0]
            method_ids_off = struct.unpack("<I", self.data[92:96])[0]

            # Extract strings
            self._extract_strings(string_ids_size, string_ids_off)

            # Extract class names
            self._extract_classes(type_ids_size, type_ids_off)

            # Extract method names
            self._extract_methods(method_ids_size, method_ids_off)

        except (struct.error, IndexError):
            self.is_valid = False

    def _extract_strings(self, count: int, offset: int) -> None:
        """Extract string table from DEX file.

        Args:
            count: Number of strings
            offset: Offset to string IDs
        """
        for i in range(count):
            try:
                str_off = struct.unpack("<I", self.data[offset + i * 4 : offset + i * 4 + 4])[0]
                str_len, data_off = self._read_uleb128(str_off)
                s = self.data[data_off : data_off + str_len].decode("utf-8", errors="replace")
                self.strings.append(s)
            except (struct.error, IndexError):
                self.strings.append("")

    def _extract_classes(self, count: int, offset: int) -> None:
        """Extract class names from DEX file.

        Args:
            count: Number of type IDs
            offset: Offset to type IDs
        """
        for i in range(count):
            try:
                desc_idx = struct.unpack("<I", self.data[offset + i * 4 : offset + i * 4 + 4])[0]
                if desc_idx < len(self.strings):
                    class_name = self.strings[desc_idx]
                    if class_name.startswith("L"):
                        self.classes.append(class_name)
            except (struct.error, IndexError):
                pass

    def _extract_methods(self, count: int, offset: int) -> None:
        """Extract method names from DEX file.

        Args:
            count: Number of method IDs
            offset: Offset to method IDs
        """
        seen = set()
        for i in range(count):
            try:
                method_offset = offset + i * 8
                name_idx = struct.unpack("<I", self.data[method_offset + 4 : method_offset + 8])[0]
                if name_idx < len(self.strings):
                    method_name = self.strings[name_idx]
                    if method_name not in seen:
                        seen.add(method_name)
                        self.methods.append(method_name)
            except (struct.error, IndexError):
                pass

    def build_stream(self) -> bytes:
        """Build memory stream for YARA scanning.

        Returns:
            Bytes containing formatted stream of strings, classes, and methods
        """
        parts = ["[STRINGS]"]
        parts.extend(self.strings)
        parts.append("[CLASSES]")
        parts.extend(self.classes)
        parts.append("[METHODS]")
        parts.extend(self.methods)

        return "\x00".join(parts).encode("utf-8", errors="replace")


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """DEX malware scanner plugin.

    This plugin detects Android malware by:
    1. Parsing DEX files to extract strings, classes, and methods
    2. Building a memory stream from extracted data
    3. Scanning the stream using YARA rules
    """

    def __init__(self):
        """Initialize the DEX plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="DEX Scan Engine",
            kmd_name="dex",
        )
        self.yara_loader = YaraRuleLoader(
            rule_subpath="yara/dex",
            fallback_prefix="Android.YARA",
            logger=self.logger,
        )

    # Expose YaraRuleLoader attributes for backward compatibility
    @property
    def rules(self):
        """Get compiled YARA rules."""
        return self.yara_loader.rules

    @property
    def compiled_rules(self):
        """Get pre-compiled YARA rules list."""
        return self.yara_loader.compiled_rules

    @property
    def loaded_files(self):
        """Get list of successfully loaded rule files."""
        return self.yara_loader.loaded_files

    @property
    def failed_files(self):
        """Get list of failed rule files with error messages."""
        return self.yara_loader.failed_files

    @property
    def rule_count(self):
        """Get total number of loaded rules."""
        return self.yara_loader.rule_count

    def _load_virus_database(self) -> int:
        """Load YARA rules for DEX scanning.

        Returns:
            0 for success (plugin can parse DEX even without rules)
        """
        return self.yara_loader.load(self.rules_paths, self.verbose)

    def scan(self, filehandle, filename, fileformat=None, filename_ex=None):
        """Scan DEX file for malware.

        Args:
            filehandle: File data (memory mapped or bytes)
            filename: Path to file
            fileformat: Format info from format() method
            filename_ex: Extended filename info

        Returns:
            Tuple of (found, malware_name, malware_id, result)
        """
        # Check if it's a DEX file
        if filehandle is None or len(filehandle) < DEX_HEADER_SIZE:
            return False, "", -1, kernel.NOT_FOUND

        if filehandle[:4] != DEX_MAGIC:
            return False, "", -1, kernel.NOT_FOUND

        try:
            # Parse DEX file
            parser = DexParser(bytes(filehandle))

            if not parser.is_valid:
                return False, "", -1, kernel.NOT_FOUND

            # Build memory stream
            stream = parser.build_stream()

            # Verbose output (show even if no rules loaded)
            if self.verbose:
                self._print_verbose_info(filename, parser, stream)

            # YARA scan
            matched, vname, _ = self.yara_loader.match(stream)
            if matched:
                return True, vname, 0, kernel.INFECTED

        except (IOError, OSError) as e:
            self.logger.debug("Scan IO error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error scanning %s: %s", filename, e)

        return False, "", -1, kernel.NOT_FOUND

    def _print_verbose_info(self, filename: str, parser: DexParser, stream: bytes) -> None:
        """Print verbose information about DEX parsing.

        Args:
            filename: Name of the file being scanned
            parser: DexParser instance
            stream: Generated memory stream
        """
        self.logger.info("-" * 79)
        self.logger.info("[*] DEX Engine")
        self.logger.info("    [-] File name: %s", os.path.basename(filename))
        self.logger.info("    [-] Strings: %s", f"{len(parser.strings):,}")
        self.logger.info("    [-] Classes: %s", f"{len(parser.classes):,}")
        self.logger.info("    [-] Methods: %s", f"{len(parser.methods):,}")
        self.logger.info("[*] Memory Stream")
        self.logger.info("    [-] Stream size: %s bytes", f"{len(stream):,}")

        if parser.classes:
            self.logger.info("[*] Classes")
            for cls in parser.classes:
                self.logger.info("    [-] %s", cls)

        if parser.methods:
            self.logger.info("[*] Methods")
            for method in parser.methods:
                self.logger.info("    [-] %s", method)

        if parser.strings:
            self.logger.info("[*] Strings")
            for s in parser.strings:
                if s:  # Skip empty strings
                    self.logger.info("    [-] %s", s)

        self.logger.info("-" * 79)

    def disinfect(self, filename: str, malware_id: int) -> bool:
        """Disinfect (delete) the infected file.

        Args:
            filename: Path to infected file
            malware_id: Malware ID from scan result

        Returns:
            True if successful, False otherwise
        """
        if not self._validate_path_input(filename, "disinfect_filename"):
            return False

        try:
            if malware_id == 0:
                filename_dir = os.path.dirname(filename) or os.getcwd()
                return k2security.safe_remove_file(filename, filename_dir)
        except (IOError, OSError, k2security.SecurityError) as e:
            self.logger.debug("Disinfect error for %s: %s", filename, e)

        return False

    def listvirus(self):
        """Get list of detectable malware.

        Returns:
            List of malware names from loaded YARA rules
        """
        return self.yara_loader.get_virus_list()

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = self.yara_loader.rule_count
        return info
