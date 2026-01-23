# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
YARA Engine Plugin

This plugin handles malware detection using external YARA rules.
Supports loading multiple YARA rule files from plugins/rules/yara folder.
"""

import os

from kicomav.plugins import kernel
from kicomav.kavcore import k2security
from kicomav.kavcore.k2plugin_base import MalwareDetectorBase
from kicomav.kavcore.k2yara import YaraRuleLoader


# -------------------------------------------------------------------------
# KavMain Class
# -------------------------------------------------------------------------
class KavMain(MalwareDetectorBase):
    """YARA-based malware detector plugin.

    This plugin provides functionality for:
    - Detecting malware using external YARA rule files
    - Loading multiple YARA rules from rules/yara folder
    - Supporting custom YARA rules with KicomAV metadata
    """

    def __init__(self):
        """Initialize the YARA Engine plugin."""
        super().__init__(
            author="Kei Choi",
            version="1.1",
            title="Yara Engine",
            kmd_name="yaraex",
        )
        self.yara_loader = YaraRuleLoader(
            rule_subpath="yara/common",
            fallback_prefix="YARA",
            logger=self.logger,
        )

    # Expose YaraRuleLoader attributes for backward compatibility
    @property
    def rules(self):
        """Get compiled YARA rules."""
        return self.yara_loader.rules

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
        """Load virus patterns from multiple YARA rules.

        Returns:
            0 for success (even if no rules found)
        """
        return self.yara_loader.load(self.rules_paths, self.verbose)

    def getinfo(self):
        """Get plugin information.

        Returns:
            Dictionary containing plugin metadata
        """
        info = super().getinfo()
        info["sig_num"] = self.yara_loader.rule_count
        return info

    def listvirus(self):
        """Get list of malware that can be detected by YARA rules.

        Returns:
            List of malware names from loaded YARA rules
        """
        return self.yara_loader.get_virus_list()

    def scan(self, filehandle, filename, fileformat, filename_ex):
        """Scan for malware using YARA rules.

        Args:
            filehandle: File data (memory mapped)
            filename: Path to file
            fileformat: Format info from format() method
            filename_ex: Extended filename info

        Returns:
            Tuple of (found, malware_name, malware_id, result)
        """
        try:
            # Exclude YARA rule files themselves
            filename_lower = filename.lower()
            if filename_lower.endswith(".yar") or filename_lower.endswith(".yara"):
                return False, "", -1, kernel.NOT_FOUND

            # YARA scan
            matched, vname, _ = self.yara_loader.match(bytes(filehandle))
            if matched:
                return True, vname, 0, kernel.INFECTED

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
            if malware_id == 0:
                filename_dir = os.path.dirname(filename) or os.getcwd()
                k2security.safe_remove_file(filename, filename_dir)
                return True

        except (IOError, OSError, k2security.SecurityError) as e:
            self.logger.debug("Disinfect error for %s: %s", filename, e)
        except Exception as e:
            self.logger.warning("Unexpected error disinfecting %s: %s", filename, e)

        return False
