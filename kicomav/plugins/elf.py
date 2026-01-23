# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)
# Reference : https://en.wikipedia.org/wiki/Executable_and_Linkable_Format

"""
ELF File Format Engine Plugin

This plugin handles ELF (Executable and Linkable Format) for scanning and analysis.
"""

import contextlib
import os
import struct

from kicomav.plugins import kavutil
from kicomav.kavcore.k2plugin_base import ArchivePluginBase

# PyInstaller section name
PYINST_SECTION = "pydata"


# -------------------------------------------------------------------------
# ELF32 class
# -------------------------------------------------------------------------
class ELF32:
    def __init__(self, mm, endian, verbose, filename, logger=None):
        self.verbose = verbose
        self.filename = filename
        self.mm = mm
        self.endian = endian
        self.program_headers = []
        self.sections = []
        self.logger = kavutil.get_logger(logger)
        self.ident = {
            0x00: "System V",
            0x01: "HP-UX",
            0x02: "NetBSD",
            0x03: "Linux",
            0x06: "Solaris",
            0x07: "AIX",
            0x08: "IRIX",
            0x09: "FreeBSD",
            0x0A: "Tru64",
            0x0B: "Novell Modesto",
            0x0C: "OpenBSD",
            0x0D: "OpenVMS",
            0x0E: "NonStop Kernel",
            0x0F: "AROS",
            0x10: "Fenix OS",
            0x11: "CloudABI",
            0x53: "Sortix",
        }
        self.machine = {
            0x02: "SPARC",
            0x03: "x86",
            0x08: "MIPS",
            0x14: "PowerPC",
            0x28: "ARM",
            0x2A: "SuperH",
            0x32: "IA-64",
            0x3E: "x86-64",
            0xB7: "AArch64",
            0xF3: "RISC-V",
        }

    def parse(self):
        fileformat = {}
        mm = self.mm

        with contextlib.suppress(ValueError, struct.error):
            # EP
            e_entry = kavutil.get_uint32(mm, 0x18, self.endian)

            # ELF header information
            e_ident = int(mm[7])
            e_machine = kavutil.get_uint16(mm, 0x12, self.endian)

            e_phoff = kavutil.get_uint32(mm, 0x1C, self.endian)
            e_shoff = kavutil.get_uint32(mm, 0x20, self.endian)
            e_phnum = kavutil.get_uint16(mm, 0x2C, self.endian)
            e_shnum = kavutil.get_uint16(mm, 0x30, self.endian)
            e_shstrndx = kavutil.get_uint16(mm, 0x32, self.endian)

            # Get program header information
            for i in range(e_phnum):
                program_header = {"Type": kavutil.get_uint32(mm, e_phoff + (0x20 * i) + 0, self.endian)}

                program_header["Flag"] = kavutil.get_uint32(mm, e_phoff + (0x20 * i) + 0x18, self.endian)
                program_header["RVA"] = kavutil.get_uint32(mm, e_phoff + (0x20 * i) + 0x8, self.endian)
                program_header["Offset"] = kavutil.get_uint32(mm, e_phoff + (0x20 * i) + 0x4, self.endian)
                program_header["Size"] = kavutil.get_uint32(mm, e_phoff + (0x20 * i) + 0x10, self.endian)

                self.program_headers.append(program_header)

            fileformat["ProgramHeaders"] = self.program_headers

            # Section name table
            name_table_off = kavutil.get_uint32(mm, e_shoff + (0x28 * e_shstrndx) + 0x10, self.endian)
            name_table_size = kavutil.get_uint32(mm, e_shoff + (0x28 * e_shstrndx) + 0x14, self.endian)
            name_table = mm[name_table_off : name_table_off + name_table_size]

            # Get section information
            for i in range(e_shnum):
                name_off = kavutil.get_uint32(mm, e_shoff + (0x28 * i), self.endian)
                section = {"Name": name_table[name_off:].decode("utf-8", "ignore").split("\x00", 1)[0]}
                section["Type"] = kavutil.get_uint32(mm, e_shoff + (0x28 * i) + 4, self.endian)
                section["Flag"] = kavutil.get_uint32(mm, e_shoff + (0x28 * i) + 8, self.endian)
                section["RVA"] = kavutil.get_uint32(mm, e_shoff + (0x28 * i) + 0xC, self.endian)
                section["Offset"] = kavutil.get_uint32(mm, e_shoff + (0x28 * i) + 0x10, self.endian)
                section["Size"] = kavutil.get_uint32(mm, e_shoff + (0x28 * i) + 0x14, self.endian)

                self.sections.append(section)

            fileformat["Sections"] = self.sections
            fileformat["EntryPoint"] = e_entry

            # Get the location of the file in the EntryPoint
            ep_raw, sec_idx = self.rva_to_off(e_entry)
            fileformat["EntryPointRaw"] = ep_raw  # EP's Raw location
            fileformat["EntryPoint_in_Section"] = sec_idx  # EP is included in the section

            if self.verbose:
                self.logger.info("-" * 79)
                kavutil.vprint("Engine")
                kavutil.vprint(None, "Engine", "elf")
                kavutil.vprint(None, "File name", os.path.split(self.filename)[-1])

                kavutil.vprint("ELF32")

                msg1 = self.ident[e_ident] if e_ident in self.ident else "Unknown"
                msg2 = self.machine[e_machine] if e_machine in self.machine else "Unknown"
                kavutil.vprint(None, "Identifies", f"{msg1} ({msg2})")

                kavutil.vprint(None, "Entry Point", f"0x{e_entry:08X}")
                kavutil.vprint(None, "Entry Point (Raw)", f"0x{ep_raw:08X}")
                kavutil.vprint(None, "Program Header Off", f"0x{e_phoff:08X}")
                kavutil.vprint(None, "Program Header Num", f"0x{e_phnum:04X}")
                kavutil.vprint(None, "Section Header Off", f"0x{e_shoff:08X}")
                kavutil.vprint(None, "Section Header Num", f"0x{e_shnum:04X}")

                if e_phnum:
                    kavutil.vprint("Program Header")
                    lines = ["    %-8s %-8s %-8s %-8s %-8s" % ("Type", "Flag", "RVA", "Offset", "Size")]
                    lines.append("    " + ("-" * 44))
                    for p in self.program_headers:
                        lines.append(
                            "    %08X %08X %08X %08X %08X" % (p["Type"], p["Flag"], p["RVA"], p["Offset"], p["Size"])
                        )
                    self.logger.info("\n".join(lines))

                if e_shnum:
                    kavutil.vprint("Section Header")
                    lines = ["    %-15s %-8s %-8s %-8s %-8s %-8s" % ("Name", "Type", "Flag", "RVA", "Offset", "Size")]
                    lines.append("    " + ("-" * (44 + 16)))
                    for p in self.sections:
                        lines.append(
                            "    %-15s %08X %08X %08X %08X %08X"
                            % (p["Name"], p["Type"], p["Flag"], p["RVA"], p["Offset"], p["Size"])
                        )
                    self.logger.info("\n".join(lines))

                kavutil.vprint("Entry Point (Raw)")
                kavutil.HexDump().Buffer(mm[:], ep_raw, 0x80)

        return fileformat

    def rva_to_off(self, t_rva):
        if len(self.sections):
            t_section = self.sections
        elif len(self.program_headers):
            t_section = self.program_headers
        else:
            t_section = []

        for section in t_section:
            size = section["Size"]
            rva = section["RVA"]

            if rva <= t_rva < rva + size:
                t_off = t_rva - rva + section["Offset"]

                return t_off, t_section.index(section)

        return t_rva, -1  # If not included in any section, return RVA


# -------------------------------------------------------------------------
# ELF64 class
# -------------------------------------------------------------------------
class ELF64:
    def __init__(self, mm, endian, verbose, filename, logger=None):
        self.filename = filename
        self.verbose = verbose
        self.mm = mm
        self.endian = endian
        self.program_headers = []
        self.sections = []
        self.logger = kavutil.get_logger(logger)

    def parse(self):
        fileformat = {}
        mm = self.mm

        with contextlib.suppress(ValueError, struct.error):
            # EP
            e_entry = kavutil.get_uint64(mm, 0x18, self.endian)

            # Section header information
            e_phoff = kavutil.get_uint64(mm, 0x20, self.endian)
            e_shoff = kavutil.get_uint64(mm, 0x28, self.endian)
            e_phnum = kavutil.get_uint16(mm, 0x38, self.endian)
            e_shnum = kavutil.get_uint16(mm, 0x3C, self.endian)
            e_shstrndx = kavutil.get_uint16(mm, 0x3E, self.endian)

            # Get program header information
            for i in range(e_phnum):
                program_header = {"Type": kavutil.get_uint32(mm, e_phoff + (0x38 * i) + 0, self.endian)}

                program_header["Flag"] = kavutil.get_uint32(mm, e_phoff + (0x38 * i) + 0x4, self.endian)
                program_header["RVA"] = kavutil.get_uint64(mm, e_phoff + (0x38 * i) + 0x10, self.endian)
                program_header["Offset"] = kavutil.get_uint64(mm, e_phoff + (0x38 * i) + 0x8, self.endian)
                program_header["Size"] = kavutil.get_uint64(mm, e_phoff + (0x38 * i) + 0x20, self.endian)

                self.program_headers.append(program_header)

            fileformat["ProgramHeaders"] = self.program_headers

            # Section name table
            name_table_off = kavutil.get_uint64(mm, e_shoff + (0x40 * e_shstrndx) + 0x18, self.endian)
            name_table_size = kavutil.get_uint64(mm, e_shoff + (0x40 * e_shstrndx) + 0x20, self.endian)
            name_table = mm[name_table_off : name_table_off + name_table_size]

            # Get section information
            for i in range(e_shnum):
                name_off = kavutil.get_uint32(mm, e_shoff + (0x40 * i), self.endian)
                section = {"Name": name_table[name_off:].decode("utf-8", "ignore").split("\x00", 1)[0]}
                section["Type"] = kavutil.get_uint32(mm, e_shoff + (0x40 * i) + 4, self.endian)
                section["Flag"] = kavutil.get_uint64(mm, e_shoff + (0x40 * i) + 8, self.endian)
                section["RVA"] = kavutil.get_uint64(mm, e_shoff + (0x40 * i) + 0x10, self.endian)
                section["Offset"] = kavutil.get_uint64(mm, e_shoff + (0x40 * i) + 0x18, self.endian)
                section["Size"] = kavutil.get_uint64(mm, e_shoff + (0x40 * i) + 0x20, self.endian)

                self.sections.append(section)

            fileformat["Sections"] = self.sections
            fileformat["EntryPoint"] = e_entry

            # Get the location of the file in the EntryPoint
            ep_raw, sec_idx = self.rva_to_off(e_entry)
            fileformat["EntryPointRaw"] = ep_raw  # EP's Raw location
            fileformat["EntryPoint_in_Section"] = sec_idx  # EP is included in the section

            if self.verbose:
                self.logger.info("-" * 79)
                kavutil.vprint("Engine")
                kavutil.vprint(None, "Engine", "elf")
                kavutil.vprint(None, "File name", os.path.split(self.filename)[-1])

                kavutil.vprint("ELF64")

                kavutil.vprint(None, "Entry Point", "0x%016X" % e_entry)
                kavutil.vprint(None, "Entry Point (Raw)", "0x%016X" % ep_raw)
                kavutil.vprint(None, "Program Header Off", "0x%016X" % e_phoff)
                kavutil.vprint(None, "Program Header Num", "0x%04X" % e_phnum)
                kavutil.vprint(None, "Section Header Off", "0x%016X" % e_shoff)
                kavutil.vprint(None, "Section Header Num", "0x%04X" % e_shnum)

                if e_shnum:
                    kavutil.vprint("Section Header")
                    lines = [
                        "    %-15s %-8s %-16s %-16s %-16s %-16s" % ("Name", "Type", "Flag", "RVA", "Offset", "Size")
                    ]
                    lines.append("    " + ("-" * (76 + 16)))
                    for p in self.sections:
                        lines.append(
                            "    %-15s %08X %016X %016X %016X %016X"
                            % (p["Name"], p["Type"], p["Flag"], p["RVA"], p["Offset"], p["Size"])
                        )
                    self.logger.info("\n".join(lines))

                kavutil.vprint("Entry Point (Raw)")
                kavutil.HexDump().Buffer(mm[:], ep_raw, 0x80)

        return fileformat

    def rva_to_off(self, t_rva):
        for section in self.sections:
            size = section["Size"]
            rva = section["RVA"]

            if rva <= t_rva < rva + size:
                t_off = t_rva - rva + section["Offset"]

                return t_off, self.sections.index(section)

        return t_rva, -1  # If not included in any section, return RVA


# -------------------------------------------------------------------------
# ELF unified class
# -------------------------------------------------------------------------
class ELF:
    def __init__(self, mm, verbose, filename, logger=None):
        self.filename = filename
        self.verbose = verbose
        self.mm = mm
        self.endian = None
        self.logger = kavutil.get_logger(logger)

    def parse(self):
        fileformat = None
        mm = self.mm

        with contextlib.suppress(ValueError):
            fileformat = self.parse_elf_header(mm)

        return fileformat

    def parse_elf_header(self, mm):
        if mm[:4] != b"\x7FELF":  # Is it an ELF header?
            raise ValueError

        bit = int(mm[4])  # Get bit
        endian = int(mm[5])  # Get endian

        if endian == 1:  # 1:little, 2:big
            self.endian = "<"
        elif endian == 2:
            self.endian = ">"
        else:
            raise ValueError

        if bit == 1:  # 32bit ELF
            e = ELF32(mm, self.endian, self.verbose, self.filename, logger=self.logger)
        elif bit == 2:  # 64bit ELF
            e = ELF64(mm, self.endian, self.verbose, self.filename, logger=self.logger)
        else:
            raise ValueError

        return e.parse()


# -------------------------------------------------------------------------
# KavMain class
# -------------------------------------------------------------------------
class KavMain(ArchivePluginBase):
    """ELF file format handler plugin.

    This plugin provides functionality for:
    - Detecting ELF (Executable and Linkable Format) files
    - Parsing ELF32 and ELF64 headers
    - Extracting section and program header information
    - Extracting embedded PyInstaller CArchive
    """

    def __init__(self):
        """Initialize the ELF plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="ELF Engine",
            kmd_name="elf",
        )

    def format(self, filehandle, filename, filename_ex):
        """Analyze and detect ELF format.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            filename_ex: Extended filename info

        Returns:
            Dictionary with format info, or empty dict if not recognized
        """
        ret = {}

        try:
            elf = ELF(filehandle, self.verbose, filename, logger=self.logger)
            fileformat = elf.parse()
            if fileformat:
                ret["ff_elf"] = {"elf": fileformat}

                # Detect PyInstaller CArchive by pydata section
                sections = fileformat.get("Sections", [])
                for section in sections:
                    if section.get("Name") == PYINST_SECTION:
                        offset = section.get("Offset", 0)
                        size = section.get("Size", 0)
                        if offset > 0 and size > 0:
                            ret["ff_elf"]["CArchive"] = {
                                "Offset": offset,
                                "Size": size,
                            }
                        break

        except (IOError, OSError) as e:
            self.logger.debug("Format detection IO error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error in format detection for %s: %s", filename, e)

        return ret

    def arclist(self, filename, fileformat, password=None):
        """List embedded archives in ELF file.

        Args:
            filename: Path to ELF file
            fileformat: Format info from format() method
            password: Optional password (not used)

        Returns:
            List of [engine_id, filename] pairs
        """
        file_scan_list = []

        try:
            if "ff_elf" in fileformat and "CArchive" in fileformat["ff_elf"]:
                carch = fileformat["ff_elf"]["CArchive"]
                off = carch["Offset"]
                size = carch["Size"]
                file_scan_list.append([f"arc_elf_carch:{off}:{size}", "CArchive"])

        except (KeyError, TypeError) as e:
            self.logger.debug("Archive list error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error listing archives in %s: %s", filename, e)

        return file_scan_list

    def unarc(self, arc_engine_id, arc_name, fname_in_arc):
        """Extract embedded archive from ELF file.

        Args:
            arc_engine_id: Engine ID (format: 'arc_elf_carch:offset:size')
            arc_name: Path to ELF file
            fname_in_arc: Name of archive to extract

        Returns:
            Extracted archive data, or None on error
        """
        if not arc_engine_id.startswith("arc_elf_carch:"):
            return None

        try:
            t = arc_engine_id.split(":")
            off = int(t[1])
            size = int(t[2])

            with open(arc_name, "rb") as fp:
                fp.seek(off)
                data = fp.read(size)

            return data

        except (IOError, OSError) as e:
            self.logger.debug("Archive extract IO error for %s in %s: %s", fname_in_arc, arc_name, e)
        except (ValueError, IndexError) as e:
            self.logger.debug("Archive extract parse error: %s", e)
        except Exception as e:
            self.logger.warning("Unexpected error extracting %s from %s: %s", fname_in_arc, arc_name, e)

        return None
