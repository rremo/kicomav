# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)
# Reference : https://en.wikipedia.org/wiki/Mach-O

"""
Mach-O File Format Engine Plugin

This plugin handles Mach-O (Mach Object) for scanning and analysis.
Supports both 32-bit and 64-bit Mach-O files, as well as Universal Binaries (Fat).
"""

import contextlib
import os
import struct

from kicomav.plugins import kavutil
from kicomav.kavcore.k2plugin_base import FileFormatPluginBase


# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------
# Magic numbers
MH_MAGIC = 0xFEEDFACE  # 32-bit, same endian
MH_CIGAM = 0xCEFAEDFE  # 32-bit, swapped endian
MH_MAGIC_64 = 0xFEEDFACF  # 64-bit, same endian
MH_CIGAM_64 = 0xCFFAEDFE  # 64-bit, swapped endian
FAT_MAGIC = 0xCAFEBABE  # Universal binary, big endian
FAT_CIGAM = 0xBEBAFECA  # Universal binary, little endian

# File types
MH_FILETYPES = {
    0x1: "MH_OBJECT",  # Relocatable object file
    0x2: "MH_EXECUTE",  # Executable file
    0x3: "MH_FVMLIB",  # Fixed VM shared library
    0x4: "MH_CORE",  # Core file
    0x5: "MH_PRELOAD",  # Preloaded executable
    0x6: "MH_DYLIB",  # Dynamic library
    0x7: "MH_DYLINKER",  # Dynamic linker
    0x8: "MH_BUNDLE",  # Bundle
    0x9: "MH_DYLIB_STUB",  # Shared library stub
    0xA: "MH_DSYM",  # Debug symbols
    0xB: "MH_KEXT_BUNDLE",  # Kernel extension
}

# CPU types
CPU_TYPES = {
    0x00000001: "VAX",
    0x00000006: "MC680x0",
    0x00000007: "x86",
    0x01000007: "x86_64",
    0x0000000A: "MC98000",
    0x0000000B: "HPPA",
    0x0000000C: "ARM",
    0x0100000C: "ARM64",
    0x0200000C: "ARM64_32",
    0x0000000D: "MC88000",
    0x0000000E: "SPARC",
    0x0000000F: "i860",
    0x00000012: "PowerPC",
    0x01000012: "PowerPC64",
}

# Load command types
LC_TYPES = {
    0x00000001: "LC_SEGMENT",
    0x00000002: "LC_SYMTAB",
    0x00000003: "LC_SYMSEG",
    0x00000004: "LC_THREAD",
    0x00000005: "LC_UNIXTHREAD",
    0x00000006: "LC_LOADFVMLIB",
    0x00000007: "LC_IDFVMLIB",
    0x00000008: "LC_IDENT",
    0x00000009: "LC_FVMFILE",
    0x0000000A: "LC_PREPAGE",
    0x0000000B: "LC_DYSYMTAB",
    0x0000000C: "LC_LOAD_DYLIB",
    0x0000000D: "LC_ID_DYLIB",
    0x0000000E: "LC_LOAD_DYLINKER",
    0x0000000F: "LC_ID_DYLINKER",
    0x00000010: "LC_PREBOUND_DYLIB",
    0x00000011: "LC_ROUTINES",
    0x00000012: "LC_SUB_FRAMEWORK",
    0x00000013: "LC_SUB_UMBRELLA",
    0x00000014: "LC_SUB_CLIENT",
    0x00000015: "LC_SUB_LIBRARY",
    0x00000016: "LC_TWOLEVEL_HINTS",
    0x00000017: "LC_PREBIND_CKSUM",
    0x80000018: "LC_LOAD_WEAK_DYLIB",
    0x00000019: "LC_SEGMENT_64",
    0x0000001A: "LC_ROUTINES_64",
    0x0000001B: "LC_UUID",
    0x8000001C: "LC_RPATH",
    0x0000001D: "LC_CODE_SIGNATURE",
    0x0000001E: "LC_SEGMENT_SPLIT_INFO",
    0x8000001F: "LC_REEXPORT_DYLIB",
    0x00000020: "LC_LAZY_LOAD_DYLIB",
    0x00000021: "LC_ENCRYPTION_INFO",
    0x00000022: "LC_DYLD_INFO",
    0x80000022: "LC_DYLD_INFO_ONLY",
    0x80000023: "LC_LOAD_UPWARD_DYLIB",
    0x00000024: "LC_VERSION_MIN_MACOSX",
    0x00000025: "LC_VERSION_MIN_IPHONEOS",
    0x00000026: "LC_FUNCTION_STARTS",
    0x00000027: "LC_DYLD_ENVIRONMENT",
    0x80000028: "LC_MAIN",
    0x00000029: "LC_DATA_IN_CODE",
    0x0000002A: "LC_SOURCE_VERSION",
    0x0000002B: "LC_DYLIB_CODE_SIGN_DRS",
    0x0000002C: "LC_ENCRYPTION_INFO_64",
    0x0000002D: "LC_LINKER_OPTION",
    0x0000002E: "LC_LINKER_OPTIMIZATION_HINT",
    0x0000002F: "LC_VERSION_MIN_TVOS",
    0x00000030: "LC_VERSION_MIN_WATCHOS",
    0x00000031: "LC_NOTE",
    0x00000032: "LC_BUILD_VERSION",
    0x80000033: "LC_DYLD_EXPORTS_TRIE",
    0x80000034: "LC_DYLD_CHAINED_FIXUPS",
    0x80000035: "LC_FILESET_ENTRY",
}


# -------------------------------------------------------------------------
# MachO32 class
# -------------------------------------------------------------------------
class MachO32:
    def __init__(self, mm, endian, verbose, filename, offset=0, logger=None):
        self.verbose = verbose
        self.filename = filename
        self.mm = mm
        self.endian = endian
        self.offset = offset  # Offset within file (for Fat binaries)
        self.load_commands = []
        self.segments = []
        self.sections = []
        self.logger = kavutil.get_logger(logger)

    def parse(self):
        fileformat = {}
        mm = self.mm
        off = self.offset

        with contextlib.suppress(ValueError, struct.error):
            # Mach-O header (32-bit)
            magic = kavutil.get_uint32(mm, off + 0x00, self.endian)
            cputype = kavutil.get_uint32(mm, off + 0x04, self.endian)
            cpusubtype = kavutil.get_uint32(mm, off + 0x08, self.endian)
            filetype = kavutil.get_uint32(mm, off + 0x0C, self.endian)
            ncmds = kavutil.get_uint32(mm, off + 0x10, self.endian)
            sizeofcmds = kavutil.get_uint32(mm, off + 0x14, self.endian)
            flags = kavutil.get_uint32(mm, off + 0x18, self.endian)

            fileformat["Magic"] = magic
            fileformat["CPUType"] = cputype
            fileformat["CPUSubType"] = cpusubtype
            fileformat["FileType"] = filetype
            fileformat["NumCommands"] = ncmds
            fileformat["SizeOfCommands"] = sizeofcmds
            fileformat["Flags"] = flags

            # Parse load commands
            cmd_offset = off + 0x1C  # Header size for 32-bit
            entrypoint = 0
            entrypoint_raw = 0

            for _ in range(ncmds):
                cmd = kavutil.get_uint32(mm, cmd_offset, self.endian)
                cmdsize = kavutil.get_uint32(mm, cmd_offset + 4, self.endian)

                load_cmd = {
                    "Cmd": cmd,
                    "CmdSize": cmdsize,
                    "CmdName": LC_TYPES.get(cmd, f"UNKNOWN(0x{cmd:08X})"),
                }
                self.load_commands.append(load_cmd)

                # LC_SEGMENT (0x1)
                if cmd == 0x1:
                    segment = self._parse_segment32(mm, cmd_offset)
                    self.segments.append(segment)
                    self.sections.extend(segment.get("Sections", []))

                # LC_UNIXTHREAD (0x5) - Entry point for older binaries
                elif cmd == 0x5:
                    # Entry point is at different offsets depending on CPU type
                    if cputype == 0x7:  # x86
                        entrypoint = kavutil.get_uint32(mm, cmd_offset + 0x38, self.endian)
                    elif cputype == 0xC:  # ARM
                        entrypoint = kavutil.get_uint32(mm, cmd_offset + 0x50, self.endian)

                # LC_MAIN (0x80000028) - Entry point for newer binaries
                elif cmd == 0x80000028:
                    entrypoint = kavutil.get_uint32(mm, cmd_offset + 8, self.endian)

                cmd_offset += cmdsize

            fileformat["LoadCommands"] = self.load_commands
            fileformat["Segments"] = self.segments
            fileformat["Sections"] = self.sections
            fileformat["EntryPoint"] = entrypoint

            # Convert entry point to raw offset
            ep_raw, sec_idx = self.rva_to_off(entrypoint)
            fileformat["EntryPointRaw"] = ep_raw
            fileformat["EntryPoint_in_Section"] = sec_idx

            if self.verbose:
                self._print_verbose(fileformat)

        return fileformat

    def _parse_segment32(self, mm, offset):
        segment = {}
        segment["SegName"] = mm[offset + 8 : offset + 24].split(b"\x00")[0].decode("utf-8", "ignore")
        segment["VMAddr"] = kavutil.get_uint32(mm, offset + 24, self.endian)
        segment["VMSize"] = kavutil.get_uint32(mm, offset + 28, self.endian)
        segment["FileOff"] = kavutil.get_uint32(mm, offset + 32, self.endian)
        segment["FileSize"] = kavutil.get_uint32(mm, offset + 36, self.endian)
        segment["MaxProt"] = kavutil.get_uint32(mm, offset + 40, self.endian)
        segment["InitProt"] = kavutil.get_uint32(mm, offset + 44, self.endian)
        segment["NumSects"] = kavutil.get_uint32(mm, offset + 48, self.endian)
        segment["Flags"] = kavutil.get_uint32(mm, offset + 52, self.endian)

        # Parse sections within segment
        sections = []
        sect_offset = offset + 56
        for _ in range(segment["NumSects"]):
            section = {}
            section["Name"] = mm[sect_offset : sect_offset + 16].split(b"\x00")[0].decode("utf-8", "ignore")
            section["SegName"] = mm[sect_offset + 16 : sect_offset + 32].split(b"\x00")[0].decode("utf-8", "ignore")
            section["Addr"] = kavutil.get_uint32(mm, sect_offset + 32, self.endian)
            section["Size"] = kavutil.get_uint32(mm, sect_offset + 36, self.endian)
            section["Offset"] = kavutil.get_uint32(mm, sect_offset + 40, self.endian)
            section["Align"] = kavutil.get_uint32(mm, sect_offset + 44, self.endian)
            section["RelOff"] = kavutil.get_uint32(mm, sect_offset + 48, self.endian)
            section["NReloc"] = kavutil.get_uint32(mm, sect_offset + 52, self.endian)
            section["Flags"] = kavutil.get_uint32(mm, sect_offset + 56, self.endian)
            sections.append(section)
            sect_offset += 68  # Section size for 32-bit

        segment["Sections"] = sections
        return segment

    def rva_to_off(self, t_rva):
        for idx, section in enumerate(self.sections):
            addr = section["Addr"]
            size = section["Size"]

            if addr <= t_rva < addr + size:
                t_off = t_rva - addr + section["Offset"]
                return t_off, idx

        return t_rva, -1

    def _print_verbose(self, fileformat):
        self.logger.info("-" * 79)
        kavutil.vprint("Engine")
        kavutil.vprint(None, "Engine", "macho")
        kavutil.vprint(None, "File name", os.path.split(self.filename)[-1])

        kavutil.vprint("Mach-O 32-bit")

        cpu_name = CPU_TYPES.get(fileformat["CPUType"], "Unknown")
        file_type = MH_FILETYPES.get(fileformat["FileType"], "Unknown")
        kavutil.vprint(None, "CPU Type", f"{cpu_name} (0x{fileformat['CPUType']:08X})")
        kavutil.vprint(None, "File Type", f"{file_type} (0x{fileformat['FileType']:X})")
        kavutil.vprint(None, "Num Commands", f"{fileformat['NumCommands']}")
        kavutil.vprint(None, "Entry Point", f"0x{fileformat['EntryPoint']:08X}")
        kavutil.vprint(None, "Entry Point (Raw)", f"0x{fileformat['EntryPointRaw']:08X}")

        if self.segments:
            kavutil.vprint("Segments")
            lines = ["    %-16s %-8s %-8s %-8s %-8s" % ("Name", "VMAddr", "VMSize", "FileOff", "FileSize")]
            lines.append("    " + ("-" * 52))
            for seg in self.segments:
                lines.append(
                    "    %-16s %08X %08X %08X %08X"
                    % (seg["SegName"], seg["VMAddr"], seg["VMSize"], seg["FileOff"], seg["FileSize"])
                )
            self.logger.info("\n".join(lines))

        if self.sections:
            kavutil.vprint("Sections")
            lines = ["    %-16s %-16s %-8s %-8s %-8s" % ("Section", "Segment", "Addr", "Size", "Offset")]
            lines.append("    " + ("-" * 60))
            for sect in self.sections:
                lines.append(
                    "    %-16s %-16s %08X %08X %08X"
                    % (sect["Name"], sect["SegName"], sect["Addr"], sect["Size"], sect["Offset"])
                )
            self.logger.info("\n".join(lines))

        if fileformat["EntryPointRaw"] > 0:
            kavutil.vprint("Entry Point (Raw)")
            kavutil.HexDump().Buffer(self.mm[:], fileformat["EntryPointRaw"], 0x80)


# -------------------------------------------------------------------------
# MachO64 class
# -------------------------------------------------------------------------
class MachO64:
    def __init__(self, mm, endian, verbose, filename, offset=0, logger=None):
        self.verbose = verbose
        self.filename = filename
        self.mm = mm
        self.endian = endian
        self.offset = offset
        self.load_commands = []
        self.segments = []
        self.sections = []
        self.logger = kavutil.get_logger(logger)

    def parse(self):
        fileformat = {}
        mm = self.mm
        off = self.offset

        with contextlib.suppress(ValueError, struct.error):
            # Mach-O header (64-bit)
            magic = kavutil.get_uint32(mm, off + 0x00, self.endian)
            cputype = kavutil.get_uint32(mm, off + 0x04, self.endian)
            cpusubtype = kavutil.get_uint32(mm, off + 0x08, self.endian)
            filetype = kavutil.get_uint32(mm, off + 0x0C, self.endian)
            ncmds = kavutil.get_uint32(mm, off + 0x10, self.endian)
            sizeofcmds = kavutil.get_uint32(mm, off + 0x14, self.endian)
            flags = kavutil.get_uint32(mm, off + 0x18, self.endian)
            reserved = kavutil.get_uint32(mm, off + 0x1C, self.endian)

            fileformat["Magic"] = magic
            fileformat["CPUType"] = cputype
            fileformat["CPUSubType"] = cpusubtype
            fileformat["FileType"] = filetype
            fileformat["NumCommands"] = ncmds
            fileformat["SizeOfCommands"] = sizeofcmds
            fileformat["Flags"] = flags

            # Parse load commands
            cmd_offset = off + 0x20  # Header size for 64-bit
            entrypoint = 0

            for _ in range(ncmds):
                cmd = kavutil.get_uint32(mm, cmd_offset, self.endian)
                cmdsize = kavutil.get_uint32(mm, cmd_offset + 4, self.endian)

                load_cmd = {
                    "Cmd": cmd,
                    "CmdSize": cmdsize,
                    "CmdName": LC_TYPES.get(cmd, f"UNKNOWN(0x{cmd:08X})"),
                }
                self.load_commands.append(load_cmd)

                # LC_SEGMENT_64 (0x19)
                if cmd == 0x19:
                    segment = self._parse_segment64(mm, cmd_offset)
                    self.segments.append(segment)
                    self.sections.extend(segment.get("Sections", []))

                # LC_UNIXTHREAD (0x5) - Entry point for older binaries
                elif cmd == 0x5:
                    if cputype == 0x01000007:  # x86_64
                        entrypoint = kavutil.get_uint64(mm, cmd_offset + 0x90, self.endian)
                    elif cputype == 0x0100000C:  # ARM64
                        entrypoint = kavutil.get_uint64(mm, cmd_offset + 0x110, self.endian)

                # LC_MAIN (0x80000028) - Entry point for newer binaries
                elif cmd == 0x80000028:
                    entrypoint = kavutil.get_uint64(mm, cmd_offset + 8, self.endian)

                cmd_offset += cmdsize

            fileformat["LoadCommands"] = self.load_commands
            fileformat["Segments"] = self.segments
            fileformat["Sections"] = self.sections
            fileformat["EntryPoint"] = entrypoint

            # Convert entry point to raw offset
            ep_raw, sec_idx = self.rva_to_off(entrypoint)
            fileformat["EntryPointRaw"] = ep_raw
            fileformat["EntryPoint_in_Section"] = sec_idx

            if self.verbose:
                self._print_verbose(fileformat)

        return fileformat

    def _parse_segment64(self, mm, offset):
        segment = {}
        segment["SegName"] = mm[offset + 8 : offset + 24].split(b"\x00")[0].decode("utf-8", "ignore")
        segment["VMAddr"] = kavutil.get_uint64(mm, offset + 24, self.endian)
        segment["VMSize"] = kavutil.get_uint64(mm, offset + 32, self.endian)
        segment["FileOff"] = kavutil.get_uint64(mm, offset + 40, self.endian)
        segment["FileSize"] = kavutil.get_uint64(mm, offset + 48, self.endian)
        segment["MaxProt"] = kavutil.get_uint32(mm, offset + 56, self.endian)
        segment["InitProt"] = kavutil.get_uint32(mm, offset + 60, self.endian)
        segment["NumSects"] = kavutil.get_uint32(mm, offset + 64, self.endian)
        segment["Flags"] = kavutil.get_uint32(mm, offset + 68, self.endian)

        # Parse sections within segment
        sections = []
        sect_offset = offset + 72
        for _ in range(segment["NumSects"]):
            section = {}
            section["Name"] = mm[sect_offset : sect_offset + 16].split(b"\x00")[0].decode("utf-8", "ignore")
            section["SegName"] = mm[sect_offset + 16 : sect_offset + 32].split(b"\x00")[0].decode("utf-8", "ignore")
            section["Addr"] = kavutil.get_uint64(mm, sect_offset + 32, self.endian)
            section["Size"] = kavutil.get_uint64(mm, sect_offset + 40, self.endian)
            section["Offset"] = kavutil.get_uint32(mm, sect_offset + 48, self.endian)
            section["Align"] = kavutil.get_uint32(mm, sect_offset + 52, self.endian)
            section["RelOff"] = kavutil.get_uint32(mm, sect_offset + 56, self.endian)
            section["NReloc"] = kavutil.get_uint32(mm, sect_offset + 60, self.endian)
            section["Flags"] = kavutil.get_uint32(mm, sect_offset + 64, self.endian)
            sections.append(section)
            sect_offset += 80  # Section size for 64-bit

        segment["Sections"] = sections
        return segment

    def rva_to_off(self, t_rva):
        for idx, section in enumerate(self.sections):
            addr = section["Addr"]
            size = section["Size"]

            if addr <= t_rva < addr + size:
                t_off = t_rva - addr + section["Offset"]
                return t_off, idx

        return t_rva, -1

    def _print_verbose(self, fileformat):
        self.logger.info("-" * 79)
        kavutil.vprint("Engine")
        kavutil.vprint(None, "Engine", "macho")
        kavutil.vprint(None, "File name", os.path.split(self.filename)[-1])

        kavutil.vprint("Mach-O 64-bit")

        cpu_name = CPU_TYPES.get(fileformat["CPUType"], "Unknown")
        file_type = MH_FILETYPES.get(fileformat["FileType"], "Unknown")
        kavutil.vprint(None, "CPU Type", f"{cpu_name} (0x{fileformat['CPUType']:08X})")
        kavutil.vprint(None, "File Type", f"{file_type} (0x{fileformat['FileType']:X})")
        kavutil.vprint(None, "Num Commands", f"{fileformat['NumCommands']}")
        kavutil.vprint(None, "Entry Point", f"0x{fileformat['EntryPoint']:016X}")
        kavutil.vprint(None, "Entry Point (Raw)", f"0x{fileformat['EntryPointRaw']:016X}")

        if self.segments:
            kavutil.vprint("Segments")
            lines = ["    %-16s %-16s %-16s %-16s %-16s" % ("Name", "VMAddr", "VMSize", "FileOff", "FileSize")]
            lines.append("    " + ("-" * 84))
            for seg in self.segments:
                lines.append(
                    "    %-16s %016X %016X %016X %016X"
                    % (seg["SegName"], seg["VMAddr"], seg["VMSize"], seg["FileOff"], seg["FileSize"])
                )
            self.logger.info("\n".join(lines))

        if self.sections:
            kavutil.vprint("Sections")
            lines = ["    %-16s %-16s %-16s %-16s %-8s" % ("Section", "Segment", "Addr", "Size", "Offset")]
            lines.append("    " + ("-" * 76))
            for sect in self.sections:
                lines.append(
                    "    %-16s %-16s %016X %016X %08X"
                    % (sect["Name"], sect["SegName"], sect["Addr"], sect["Size"], sect["Offset"])
                )
            self.logger.info("\n".join(lines))

        if fileformat["EntryPointRaw"] > 0:
            kavutil.vprint("Entry Point (Raw)")
            kavutil.HexDump().Buffer(self.mm[:], fileformat["EntryPointRaw"], 0x80)


# -------------------------------------------------------------------------
# FatBinary class (Universal Binary)
# -------------------------------------------------------------------------
class FatBinary:
    def __init__(self, mm, verbose, filename, logger=None):
        self.verbose = verbose
        self.filename = filename
        self.mm = mm
        self.archs = []
        self.logger = kavutil.get_logger(logger)

    def parse(self):
        fileformat = {}
        mm = self.mm

        with contextlib.suppress(ValueError, struct.error):
            magic = kavutil.get_uint32(mm, 0, ">")

            if magic == FAT_MAGIC:
                endian = ">"
            elif magic == FAT_CIGAM:
                endian = "<"
            else:
                raise ValueError("Not a Fat binary")

            nfat_arch = kavutil.get_uint32(mm, 4, endian)

            # Validate: Fat binary should have reasonable number of architectures (1-10)
            # Java class files also start with 0xCAFEBABE but have version numbers here
            if nfat_arch == 0 or nfat_arch > 10:
                raise ValueError("Invalid number of architectures (likely Java class file)")

            # Validate: File should be large enough for architecture descriptors
            # Header (8 bytes) + nfat_arch * fat_arch struct (20 bytes each)
            min_size = 8 + nfat_arch * 20
            if len(mm) < min_size:
                raise ValueError("File too small for Fat binary header")

            # Validate: First architecture should have valid CPU type
            first_cpu = kavutil.get_uint32(mm, 8, endian)
            if first_cpu not in CPU_TYPES:
                raise ValueError("Invalid CPU type (likely not a Fat binary)")

            fileformat["NumArchs"] = nfat_arch
            fileformat["Architectures"] = []

            arch_offset = 8
            for i in range(nfat_arch):
                arch = {}
                arch["CPUType"] = kavutil.get_uint32(mm, arch_offset, endian)
                arch["CPUSubType"] = kavutil.get_uint32(mm, arch_offset + 4, endian)
                arch["Offset"] = kavutil.get_uint32(mm, arch_offset + 8, endian)
                arch["Size"] = kavutil.get_uint32(mm, arch_offset + 12, endian)
                arch["Align"] = kavutil.get_uint32(mm, arch_offset + 16, endian)

                # Parse the embedded Mach-O
                macho = MachO(mm, self.verbose, self.filename, offset=arch["Offset"], logger=self.logger)
                arch["MachO"] = macho.parse()

                fileformat["Architectures"].append(arch)
                self.archs.append(arch)
                arch_offset += 20

            if self.verbose:
                self._print_verbose(fileformat)

        return fileformat

    def _print_verbose(self, fileformat):
        self.logger.info("-" * 79)
        kavutil.vprint("Engine")
        kavutil.vprint(None, "Engine", "macho")
        kavutil.vprint(None, "File name", os.path.split(self.filename)[-1])

        kavutil.vprint("Universal Binary (Fat)")
        kavutil.vprint(None, "Num Architectures", f"{fileformat['NumArchs']}")

        kavutil.vprint("Architectures")
        lines = ["    %-12s %-10s %-10s %-10s" % ("CPU", "Offset", "Size", "Align")]
        lines.append("    " + ("-" * 46))
        for arch in self.archs:
            cpu_name = CPU_TYPES.get(arch["CPUType"], f"0x{arch['CPUType']:08X}")
            lines.append("    %-12s %08X   %08X   %08X" % (cpu_name, arch["Offset"], arch["Size"], arch["Align"]))
        self.logger.info("\n".join(lines))


# -------------------------------------------------------------------------
# MachO unified class
# -------------------------------------------------------------------------
class MachO:
    def __init__(self, mm, verbose, filename, offset=0, logger=None):
        self.filename = filename
        self.verbose = verbose
        self.mm = mm
        self.offset = offset
        self.endian = None
        self.logger = kavutil.get_logger(logger)

    def parse(self):
        fileformat = None
        mm = self.mm

        with contextlib.suppress(ValueError):
            fileformat = self.parse_macho_header(mm)

        return fileformat

    def parse_macho_header(self, mm):
        off = self.offset
        magic = kavutil.get_uint32(mm, off, "<")

        # Check for Fat binary first
        if magic in (FAT_MAGIC, FAT_CIGAM) and self.offset == 0:
            fat = FatBinary(mm, self.verbose, self.filename, logger=self.logger)
            return fat.parse()

        # Determine endianness and bit width
        if magic == MH_MAGIC:  # 32-bit, little endian
            self.endian = "<"
            m = MachO32(mm, self.endian, self.verbose, self.filename, offset=off, logger=self.logger)
        elif magic == MH_CIGAM:  # 32-bit, big endian
            self.endian = ">"
            m = MachO32(mm, self.endian, self.verbose, self.filename, offset=off, logger=self.logger)
        elif magic == MH_MAGIC_64:  # 64-bit, little endian
            self.endian = "<"
            m = MachO64(mm, self.endian, self.verbose, self.filename, offset=off, logger=self.logger)
        elif magic == MH_CIGAM_64:  # 64-bit, big endian
            self.endian = ">"
            m = MachO64(mm, self.endian, self.verbose, self.filename, offset=off, logger=self.logger)
        else:
            raise ValueError("Not a valid Mach-O file")

        return m.parse()


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(FileFormatPluginBase):
    """Mach-O file format handler plugin.

    This plugin provides functionality for:
    - Detecting Mach-O (Mach Object) files
    - Parsing Mach-O 32-bit and 64-bit headers
    - Parsing Universal Binaries (Fat binaries)
    - Extracting segment and section information
    - Extracting load commands
    """

    def __init__(self):
        """Initialize the Mach-O plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.0",
            title="Mach-O Engine",
            kmd_name="macho",
        )

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect Mach-O format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or empty dict if not recognized
        """
        ret = {}

        try:
            # Quick magic check before full parsing
            if len(filehandle) < 4:
                return ret

            magic = kavutil.get_uint32(filehandle, 0, "<")
            valid_magics = (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC, FAT_CIGAM)

            if magic not in valid_magics:
                return ret

            macho = MachO(filehandle, self.verbose, filename, logger=self.logger)
            fileformat = macho.parse()
            if fileformat:
                ret["ff_macho"] = {"macho": fileformat}

        except (IOError, OSError) as e:
            self.logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return ret
