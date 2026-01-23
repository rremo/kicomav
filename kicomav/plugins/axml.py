# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
AXML (Android Binary XML) Scan Engine Plugin

This plugin detects Android malware by parsing AndroidManifest.xml files
and scanning extracted information using YARA rules.

Extracts:
- Package name
- Permissions
- Services (including Accessibility, Device Admin)
- Receivers and Intent Filters
- Activities
- Application flags (debuggable, allowBackup, etc.)
"""

import struct
import os
from typing import Optional

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.k2plugin_base import MalwareDetectorBase
from kicomav.kavcore.k2yara import YaraRuleLoader


# -------------------------------------------------------------------------
# AXML Constants
# -------------------------------------------------------------------------
AXML_MAGIC = 0x00080003
AXML_HEADER_SIZE = 8

# Chunk types
STRING_POOL_TYPE = 0x001C0001
RESOURCE_MAP_TYPE = 0x00080180
START_NAMESPACE_TYPE = 0x00100100
END_NAMESPACE_TYPE = 0x00100101
START_ELEMENT_TYPE = 0x00100102
END_ELEMENT_TYPE = 0x00100103
CDATA_TYPE = 0x00100104

# Known element and attribute names
ELEMENT_MANIFEST = "manifest"
ELEMENT_APPLICATION = "application"
ELEMENT_USES_PERMISSION = "uses-permission"
ELEMENT_PERMISSION = "permission"
ELEMENT_SERVICE = "service"
ELEMENT_RECEIVER = "receiver"
ELEMENT_ACTIVITY = "activity"
ELEMENT_INTENT_FILTER = "intent-filter"
ELEMENT_ACTION = "action"
ELEMENT_META_DATA = "meta-data"

ATTR_PACKAGE = "package"
ATTR_NAME = "name"
ATTR_VERSION_CODE = "versionCode"
ATTR_VERSION_NAME = "versionName"
ATTR_MIN_SDK = "minSdkVersion"
ATTR_TARGET_SDK = "targetSdkVersion"
ATTR_DEBUGGABLE = "debuggable"
ATTR_ALLOW_BACKUP = "allowBackup"
ATTR_USES_CLEARTEXT = "usesCleartextTraffic"
ATTR_EXPORTED = "exported"
ATTR_PERMISSION = "permission"


# -------------------------------------------------------------------------
# AXML Parser Class
# -------------------------------------------------------------------------
class AXMLParser:
    """Parser for Android Binary XML (AXML) format."""

    def __init__(self, data: bytes):
        """Initialize AXML parser with file data.

        Args:
            data: Raw bytes of AXML file
        """
        self.data = data
        self.is_valid = False

        # String pool
        self.strings: list[str] = []

        # Extracted information
        self.package: str = ""
        self.version_code: str = ""
        self.version_name: str = ""
        self.min_sdk: str = ""
        self.target_sdk: str = ""

        # Flags
        self.flags: list[str] = []

        # Components
        self.permissions: list[str] = []
        self.services: list[tuple[str, list[str]]] = []  # (name, [bound_permissions])
        self.receivers: list[tuple[str, list[str]]] = []  # (name, [intent_actions])
        self.activities: list[tuple[str, list[str]]] = []  # (name, [intent_actions])

        # Intent filters (current context during parsing)
        self._current_element_stack: list[str] = []
        self._current_component: Optional[str] = None
        self._current_component_type: Optional[str] = None
        self._current_intents: list[str] = []
        self._current_permissions: list[str] = []

        if self._validate_header():
            self._parse()

    def _validate_header(self) -> bool:
        """Validate AXML file header.

        Returns:
            True if valid AXML file, False otherwise
        """
        if len(self.data) < AXML_HEADER_SIZE:
            return False

        magic = struct.unpack("<I", self.data[0:4])[0]
        if magic != AXML_MAGIC:
            return False

        file_size = struct.unpack("<I", self.data[4:8])[0]
        if file_size > len(self.data):
            return False

        self.is_valid = True
        return True

    def _parse(self) -> None:
        """Parse AXML file and extract information."""
        try:
            offset = AXML_HEADER_SIZE

            while offset < len(self.data) - 8:
                chunk_type = struct.unpack("<I", self.data[offset : offset + 4])[0]
                chunk_size = struct.unpack("<I", self.data[offset + 4 : offset + 8])[0]

                if chunk_size < 8 or offset + chunk_size > len(self.data):
                    break

                if chunk_type == STRING_POOL_TYPE:
                    self._parse_string_pool(offset)
                elif chunk_type == START_ELEMENT_TYPE:
                    self._parse_start_element(offset)
                elif chunk_type == END_ELEMENT_TYPE:
                    self._parse_end_element(offset)

                offset += chunk_size

        except (struct.error, IndexError):
            self.is_valid = False

    def _parse_string_pool(self, offset: int) -> None:
        """Parse string pool chunk.

        Args:
            offset: Offset to string pool chunk
        """
        try:
            chunk_size = struct.unpack("<I", self.data[offset + 4 : offset + 8])[0]
            string_count = struct.unpack("<I", self.data[offset + 8 : offset + 12])[0]
            # style_count = struct.unpack("<I", self.data[offset + 12 : offset + 16])[0]
            flags = struct.unpack("<I", self.data[offset + 16 : offset + 20])[0]
            strings_start = struct.unpack("<I", self.data[offset + 20 : offset + 24])[0]

            is_utf8 = (flags & 0x100) != 0

            # Read string offsets
            offsets_start = offset + 28
            string_offsets = []
            for i in range(string_count):
                off = struct.unpack("<I", self.data[offsets_start + i * 4 : offsets_start + i * 4 + 4])[0]
                string_offsets.append(off)

            # Read strings
            strings_base = offset + strings_start
            for i, str_off in enumerate(string_offsets):
                try:
                    s = self._read_string(strings_base + str_off, is_utf8)
                    self.strings.append(s)
                except (IndexError, UnicodeDecodeError):
                    self.strings.append("")

        except (struct.error, IndexError):
            pass

    def _read_string(self, offset: int, is_utf8: bool) -> str:
        """Read a string from the string pool.

        Args:
            offset: Offset to string data
            is_utf8: True if UTF-8 encoded, False if UTF-16

        Returns:
            Decoded string
        """
        if is_utf8:
            # UTF-8: two length bytes (chars, bytes) followed by data
            char_len = self.data[offset]
            if char_len & 0x80:
                char_len = ((char_len & 0x7F) << 8) | self.data[offset + 1]
                offset += 2
            else:
                offset += 1

            byte_len = self.data[offset]
            if byte_len & 0x80:
                byte_len = ((byte_len & 0x7F) << 8) | self.data[offset + 1]
                offset += 2
            else:
                offset += 1

            return self.data[offset : offset + byte_len].decode("utf-8", errors="replace")
        else:
            # UTF-16: length (2 bytes) followed by data
            length = struct.unpack("<H", self.data[offset : offset + 2])[0]
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | struct.unpack("<H", self.data[offset + 2 : offset + 4])[0]
                offset += 4
            else:
                offset += 2

            return self.data[offset : offset + length * 2].decode("utf-16-le", errors="replace")

    def _get_string(self, index: int) -> str:
        """Get string by index from string pool.

        Args:
            index: String index

        Returns:
            String value or empty string if invalid
        """
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""

    def _parse_start_element(self, offset: int) -> None:
        """Parse start element chunk.

        Args:
            offset: Offset to start element chunk
        """
        try:
            # Element name
            name_idx = struct.unpack("<I", self.data[offset + 20 : offset + 24])[0]
            element_name = self._get_string(name_idx)

            self._current_element_stack.append(element_name)

            # Attributes
            attr_start = struct.unpack("<H", self.data[offset + 24 : offset + 26])[0]
            attr_size = struct.unpack("<H", self.data[offset + 26 : offset + 28])[0]
            attr_count = struct.unpack("<H", self.data[offset + 28 : offset + 30])[0]

            attrs = {}
            attrs_offset = offset + 36  # Header size

            for i in range(attr_count):
                attr_offset = attrs_offset + i * 20  # Each attribute is 20 bytes
                if attr_offset + 20 > len(self.data):
                    break

                # ns_idx = struct.unpack("<I", self.data[attr_offset : attr_offset + 4])[0]
                attr_name_idx = struct.unpack("<I", self.data[attr_offset + 4 : attr_offset + 8])[0]
                raw_value_idx = struct.unpack("<I", self.data[attr_offset + 8 : attr_offset + 12])[0]
                # typed_value_size = struct.unpack("<H", self.data[attr_offset + 12 : attr_offset + 14])[0]
                # typed_value_res0 = self.data[attr_offset + 14]
                typed_value_type = self.data[attr_offset + 15]
                typed_value_data = struct.unpack("<I", self.data[attr_offset + 16 : attr_offset + 20])[0]

                attr_name = self._get_string(attr_name_idx)

                # Get attribute value
                if raw_value_idx != 0xFFFFFFFF:
                    attr_value = self._get_string(raw_value_idx)
                elif typed_value_type == 0x03:  # String reference
                    attr_value = self._get_string(typed_value_data)
                elif typed_value_type == 0x10:  # Integer
                    attr_value = str(typed_value_data)
                elif typed_value_type == 0x12:  # Boolean
                    attr_value = "true" if typed_value_data != 0 else "false"
                else:
                    attr_value = str(typed_value_data)

                attrs[attr_name] = attr_value

            # Process element based on type
            self._process_element(element_name, attrs)

        except (struct.error, IndexError):
            pass

    def _parse_end_element(self, offset: int) -> None:
        """Parse end element chunk.

        Args:
            offset: Offset to end element chunk
        """
        try:
            name_idx = struct.unpack("<I", self.data[offset + 20 : offset + 24])[0]
            element_name = self._get_string(name_idx)

            # Handle component end
            if element_name in (ELEMENT_SERVICE, ELEMENT_RECEIVER, ELEMENT_ACTIVITY):
                self._finish_component()

            if self._current_element_stack and self._current_element_stack[-1] == element_name:
                self._current_element_stack.pop()

        except (struct.error, IndexError):
            pass

    def _process_element(self, name: str, attrs: dict[str, str]) -> None:
        """Process parsed element.

        Args:
            name: Element name
            attrs: Element attributes
        """
        if name == ELEMENT_MANIFEST:
            self.package = attrs.get(ATTR_PACKAGE, "")
            self.version_code = attrs.get(ATTR_VERSION_CODE, "")
            self.version_name = attrs.get(ATTR_VERSION_NAME, "")

        elif name == ELEMENT_APPLICATION:
            if attrs.get(ATTR_DEBUGGABLE) == "true":
                self.flags.append("debuggable")
            if attrs.get(ATTR_ALLOW_BACKUP) == "true":
                self.flags.append("allowBackup")
            if attrs.get(ATTR_USES_CLEARTEXT) == "true":
                self.flags.append("usesCleartextTraffic")

        elif name == ELEMENT_USES_PERMISSION:
            perm = attrs.get(ATTR_NAME, "")
            if perm and perm not in self.permissions:
                self.permissions.append(perm)

        elif name in (ELEMENT_SERVICE, ELEMENT_RECEIVER, ELEMENT_ACTIVITY):
            # Start new component
            self._finish_component()  # Finish any previous component
            self._current_component = attrs.get(ATTR_NAME, "")
            self._current_component_type = name
            self._current_intents = []
            self._current_permissions = []

            # Check for bound permissions
            perm = attrs.get(ATTR_PERMISSION, "")
            if perm:
                self._current_permissions.append(perm)

            # Check for exported
            if attrs.get(ATTR_EXPORTED) == "true":
                self._current_intents.append("exported")

        elif name == ELEMENT_ACTION:
            action = attrs.get(ATTR_NAME, "")
            if action:
                # Extract action name (e.g., "BOOT_COMPLETED" from full intent)
                action_short = action.split(".")[-1] if "." in action else action
                self._current_intents.append(action_short)

        elif name == ELEMENT_META_DATA:
            # Could track meta-data if needed
            pass

    def _finish_component(self) -> None:
        """Finish processing current component."""
        if self._current_component and self._current_component_type:
            info = self._current_permissions + self._current_intents

            if self._current_component_type == ELEMENT_SERVICE:
                self.services.append((self._current_component, info))
            elif self._current_component_type == ELEMENT_RECEIVER:
                self.receivers.append((self._current_component, info))
            elif self._current_component_type == ELEMENT_ACTIVITY:
                self.activities.append((self._current_component, info))

        self._current_component = None
        self._current_component_type = None
        self._current_intents = []
        self._current_permissions = []

    def build_stream(self) -> bytes:
        """Build memory stream for YARA scanning.

        Returns:
            Bytes containing formatted stream of extracted information
        """
        parts = []

        # Package info
        parts.append("[PACKAGE]")
        if self.package:
            parts.append(self.package)

        if self.version_code:
            parts.append("[VERSION]")
            parts.append(self.version_code)

        if self.min_sdk:
            parts.append("[MIN_SDK]")
            parts.append(self.min_sdk)

        if self.target_sdk:
            parts.append("[TARGET_SDK]")
            parts.append(self.target_sdk)

        # Flags
        if self.flags:
            parts.append("[FLAGS]")
            parts.extend(self.flags)

        # Permissions
        if self.permissions:
            parts.append("[PERMISSIONS]")
            parts.extend(self.permissions)

        # Services
        if self.services:
            parts.append("[SERVICES]")
            for name, info in self.services:
                if info:
                    parts.append(f"{name}:{','.join(info)}")
                else:
                    parts.append(name)

        # Receivers
        if self.receivers:
            parts.append("[RECEIVERS]")
            for name, info in self.receivers:
                if info:
                    parts.append(f"{name}:{','.join(info)}")
                else:
                    parts.append(name)

        # Activities
        if self.activities:
            parts.append("[ACTIVITIES]")
            for name, info in self.activities:
                if info:
                    parts.append(f"{name}:{','.join(info)}")
                else:
                    parts.append(name)

        # Also include raw strings from string pool that might be useful
        # Filter for permission-like and intent-like strings
        interesting_strings = []
        for s in self.strings:
            if any(
                keyword in s.lower()
                for keyword in ["permission", "intent", "action", "receiver", "service", "activity"]
            ):
                if s not in interesting_strings:
                    interesting_strings.append(s)

        if interesting_strings:
            parts.append("[RAW_STRINGS]")
            parts.extend(interesting_strings)

        return "\n".join(parts).encode("utf-8", errors="replace")


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """AXML (AndroidManifest.xml) malware scanner plugin.

    This plugin detects Android malware by:
    1. Parsing AndroidManifest.xml (AXML format)
    2. Extracting package info, permissions, components, flags
    3. Building a memory stream from extracted data
    4. Scanning the stream using YARA rules
    """

    def __init__(self):
        """Initialize the AXML plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="AXML Scan Engine",
            kmd_name="axml",
        )
        self.yara_loader = YaraRuleLoader(
            rule_subpath="yara/axml",
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
        """Load YARA rules for AXML scanning.

        Returns:
            0 for success (plugin can parse AXML even without rules)
        """
        return self.yara_loader.load(self.rules_paths, self.verbose)

    def scan(self, filehandle, filename, fileformat=None, filename_ex=None):
        """Scan AndroidManifest.xml (AXML) file for malware.

        Args:
            filehandle: File data (memory mapped or bytes)
            filename: Path to file
            fileformat: Format info from format() method
            filename_ex: Extended filename info

        Returns:
            Tuple of (found, malware_name, malware_id, result)
        """
        # Check basic validity
        if filehandle is None or len(filehandle) < AXML_HEADER_SIZE:
            return False, "", -1, kernel.NOT_FOUND

        # Check AXML magic
        try:
            magic = struct.unpack("<I", filehandle[:4])[0]
            if magic != AXML_MAGIC:
                return False, "", -1, kernel.NOT_FOUND
        except (struct.error, IndexError):
            return False, "", -1, kernel.NOT_FOUND

        try:
            # Parse AXML file
            parser = AXMLParser(bytes(filehandle))

            if not parser.is_valid:
                return False, "", -1, kernel.NOT_FOUND

            # Build memory stream
            stream = parser.build_stream()

            # Verbose output
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

    def _print_verbose_info(self, filename: str, parser: AXMLParser, stream: bytes) -> None:
        """Print verbose information about AXML parsing.

        Args:
            filename: Name of the file being scanned
            parser: AXMLParser instance
            stream: Generated memory stream
        """
        self.logger.info("-" * 79)
        self.logger.info("[*] AXML Engine")
        self.logger.info("    [-] File name: %s", os.path.basename(filename))
        self.logger.info("    [-] Package: %s", parser.package if parser.package else "(unknown)")
        self.logger.info("    [-] Version Code: %s", parser.version_code if parser.version_code else "(unknown)")
        self.logger.info("    [-] Version Name: %s", parser.version_name if parser.version_name else "(unknown)")
        self.logger.info("    [-] Strings: %s", f"{len(parser.strings):,}")
        self.logger.info("    [-] Permissions: %s", f"{len(parser.permissions):,}")
        self.logger.info("    [-] Services: %s", f"{len(parser.services):,}")
        self.logger.info("    [-] Receivers: %s", f"{len(parser.receivers):,}")
        self.logger.info("    [-] Activities: %s", f"{len(parser.activities):,}")
        self.logger.info("    [-] Flags: %s", ", ".join(parser.flags) if parser.flags else "none")

        if parser.permissions:
            self.logger.info("[*] Permissions")
            for perm in parser.permissions:
                self.logger.info("    [-] %s", perm)

        if parser.services:
            self.logger.info("[*] Services")
            for name, info in parser.services:
                self.logger.info("    [-] %s: %s", name, ", ".join(info) if info else "none")

        if parser.receivers:
            self.logger.info("[*] Receivers")
            for name, intents in parser.receivers:
                self.logger.info("    [-] %s: %s", name, ", ".join(intents) if intents else "none")

        if parser.activities:
            self.logger.info("[*] Activities")
            for name, intents in parser.activities:
                self.logger.info("    [-] %s: %s", name, ", ".join(intents) if intents else "none")

        # Show full memory stream
        self.logger.info("[*] Memory Stream (%s bytes)", f"{len(stream):,}")
        stream_text = stream.decode("utf-8", errors="replace")
        for line in stream_text.split("\n"):
            if line:
                self.logger.info("    %s", line)

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
