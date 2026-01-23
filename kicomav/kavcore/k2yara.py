# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
YARA Rule Loading Utility

Provides unified YARA rule loading and matching functionality for plugins.
Supports source files (.yar, .yara), compiled files (.yac, .yarc), and ZIP archives.
"""

import logging
import warnings
import zipfile
from pathlib import Path
from typing import Optional

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraRuleLoader:
    """Unified YARA rule loader for KicomAV plugins.

    Supports:
    - Source files: .yar, .yara
    - Compiled files: .yac, .yarc
    - ZIP archives containing source files

    Example:
        loader = YaraRuleLoader(
            rule_subpath="yara/dex",
            fallback_prefix="Android.YARA"
        )
        result = loader.load(rules_paths, verbose=True)
        if loader.has_rules():
            matched, vname, info = loader.match(data)
    """

    def __init__(
        self,
        rule_subpath: str,
        fallback_prefix: str = "YARA",
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize YARA rule loader.

        Args:
            rule_subpath: Subdirectory for rules (e.g., "yara/dex", "yara/axml")
            fallback_prefix: Prefix for virus names when KicomAV meta is missing
            logger: Optional logger instance
        """
        self.rule_subpath = rule_subpath
        self.fallback_prefix = fallback_prefix
        self.logger = logger or logging.getLogger(__name__)

        self.rules: Optional[object] = None  # Compiled from source files
        self.compiled_rules: list = []  # Pre-compiled rule objects
        self.rule_count: int = 0
        self.virus_names: list[str] = []
        self.loaded_files: list[str] = []
        self.failed_files: list[tuple[str, str]] = []

    def _get_rule_paths(self, rules_paths: dict) -> list[Path]:
        """Get valid rule directory paths from configuration.

        Args:
            rules_paths: Dictionary with 'system' and 'user' paths

        Returns:
            List of valid Path objects
        """
        paths = []
        for key in ["system", "user"]:
            base_path = rules_paths.get(key)
            if base_path:
                full_path = Path(base_path) / self.rule_subpath
                if full_path.exists() and full_path.is_dir():
                    paths.append(full_path)
        return paths

    def _extract_virus_name(self, rule) -> str:
        """Extract virus name from rule metadata.

        Args:
            rule: YARA rule object

        Returns:
            Virus name string
        """
        if "KicomAV" in rule.meta:
            return rule.meta["KicomAV"]
        return f"{self.fallback_prefix}.{rule.identifier}"

    def _load_compiled_rules(self, rules_dirs: list[Path], verbose: bool) -> None:
        """Load pre-compiled YARA rules (.yac, .yarc files).

        Args:
            rules_dirs: List of directories to search
            verbose: Whether to log verbose info
        """
        if not YARA_AVAILABLE:
            return

        for rules_dir in rules_dirs:
            compiled_files = list(rules_dir.glob("**/*.yac")) + list(rules_dir.glob("**/*.yarc"))
            for compiled_file in compiled_files:
                try:
                    compiled_rules = yara.load(filepath=str(compiled_file))
                    self.compiled_rules.append(compiled_rules)
                    self.loaded_files.append(str(compiled_file))

                    for rule in compiled_rules:
                        self.rule_count += 1
                        self.virus_names.append(self._extract_virus_name(rule))

                    if verbose:
                        self.logger.info("Loaded compiled YARA rules: %s", compiled_file)
                except yara.Error as e:
                    self.failed_files.append((str(compiled_file), str(e)))
                    self.logger.debug("Failed to load compiled rules %s: %s", compiled_file, e)

    def _collect_source_files(self, rules_dirs: list[Path]) -> dict[str, tuple[str, str]]:
        """Collect YARA source files from directories and ZIP archives.

        Args:
            rules_dirs: List of directories to search

        Returns:
            Dictionary mapping namespace to (source_content, source_path)
        """
        sources: dict[str, tuple[str, str]] = {}

        def add_source(name: str, content: str, path: str) -> None:
            namespace = name
            counter = 1
            original = namespace
            while namespace in sources:
                namespace = f"{original}_{counter}"
                counter += 1
            sources[namespace] = (content, path)

        # Collect .yar and .yara files
        for rules_dir in rules_dirs:
            for rule_file in list(rules_dir.glob("**/*.yar")) + list(rules_dir.glob("**/*.yara")):
                try:
                    with open(rule_file, "r", encoding="utf-8") as f:
                        source = f.read()
                    add_source(rule_file.stem, source, str(rule_file))
                except (IOError, OSError) as e:
                    self.failed_files.append((str(rule_file), str(e)))
                    self.logger.debug("Failed to read %s: %s", rule_file, e)

        # Collect from ZIP files
        for rules_dir in rules_dirs:
            for zip_path in rules_dir.glob("**/*.zip"):
                try:
                    with zipfile.ZipFile(zip_path, "r") as zf:
                        for name in zf.namelist():
                            name_lower = name.lower()
                            if name_lower.endswith(".yar") or name_lower.endswith(".yara"):
                                try:
                                    source = zf.read(name).decode("utf-8")
                                    rule_name = Path(name).stem
                                    add_source(rule_name, source, f"{zip_path}:{name}")
                                except (IOError, OSError, UnicodeDecodeError) as e:
                                    self.failed_files.append((f"{zip_path}:{name}", str(e)))
                except zipfile.BadZipFile as e:
                    self.failed_files.append((str(zip_path), str(e)))
                except (IOError, OSError) as e:
                    self.failed_files.append((str(zip_path), str(e)))

        return sources

    def _compile_sources(self, sources: dict[str, tuple[str, str]]) -> None:
        """Validate and compile source rules.

        Args:
            sources: Dictionary mapping namespace to (source_content, source_path)
        """
        if not YARA_AVAILABLE or not sources:
            return

        # Validate each rule individually
        valid_sources: dict[str, str] = {}
        for namespace, (source, filepath) in sources.items():
            try:
                yara.compile(source=source)
                valid_sources[namespace] = source
                self.loaded_files.append(filepath)
            except yara.SyntaxError as e:
                self.failed_files.append((filepath, str(e)))
                self.logger.debug("YARA syntax error in %s: %s", filepath, e)
            except yara.Error as e:
                self.failed_files.append((filepath, str(e)))
                self.logger.debug("YARA load error in %s: %s", filepath, e)

        if not valid_sources:
            return

        # Compile all valid rules together
        try:
            self.rules = yara.compile(sources=valid_sources)

            for rule in self.rules:
                self.rule_count += 1
                self.virus_names.append(self._extract_virus_name(rule))
        except yara.Error as e:
            self.logger.debug("YARA rule compile error: %s", e)
            self.rules = None

    def load(self, rules_paths: dict, verbose: bool = False) -> int:
        """Load YARA rules from configured paths.

        Args:
            rules_paths: Dictionary with 'system' and 'user' base paths
            verbose: Whether to log verbose information

        Returns:
            0 for success (even if no rules found, allows parsing-only mode)
        """
        # Reset state
        self.rules = None
        self.compiled_rules = []
        self.rule_count = 0
        self.virus_names = []
        self.loaded_files = []
        self.failed_files = []

        if not YARA_AVAILABLE:
            if verbose:
                self.logger.info("YARA module not available - parsing only mode")
            return 0

        rules_dirs = self._get_rule_paths(rules_paths)

        if not rules_dirs:
            if verbose:
                self.logger.info("No YARA rules paths configured for %s", self.rule_subpath)
            return 0

        # Load pre-compiled rules
        self._load_compiled_rules(rules_dirs, verbose)

        # Collect and compile source files
        sources = self._collect_source_files(rules_dirs)
        self._compile_sources(sources)

        if verbose:
            if self.rule_count > 0:
                self.logger.info(
                    "Loaded %d YARA files (%d rules), %d failed",
                    len(self.loaded_files),
                    self.rule_count,
                    len(self.failed_files),
                )
            else:
                self.logger.info("No YARA rules found - parsing only mode")

        return 0

    def has_rules(self) -> bool:
        """Check if any rules are loaded.

        Returns:
            True if rules are available for matching
        """
        return self.rules is not None or len(self.compiled_rules) > 0

    def match(self, data: bytes) -> tuple[bool, str, dict]:
        """Match data against loaded rules.

        Args:
            data: Bytes to scan

        Returns:
            Tuple of (matched, virus_name, rule_info)
            - matched: True if malware detected
            - virus_name: Name of detected malware (empty if not matched)
            - rule_info: Dictionary with 'namespace', 'rule', 'meta' (empty if not matched)
        """
        if not self.has_rules():
            return False, "", {}

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=RuntimeWarning, message="too many matches")

            # Scan with compiled source rules
            if self.rules is not None:
                matches = self.rules.match(data=data)
                if matches:
                    match = matches[0]
                    vname = match.meta.get("KicomAV") or f"{self.fallback_prefix}.{match.namespace}.{match.rule}"
                    return (
                        True,
                        vname,
                        {
                            "namespace": match.namespace,
                            "rule": match.rule,
                            "meta": dict(match.meta),
                        },
                    )

            # Scan with pre-compiled rules
            for compiled_rules in self.compiled_rules:
                matches = compiled_rules.match(data=data)
                if matches:
                    match = matches[0]
                    vname = match.meta.get("KicomAV") or f"{self.fallback_prefix}.{match.namespace}.{match.rule}"
                    return (
                        True,
                        vname,
                        {
                            "namespace": match.namespace,
                            "rule": match.rule,
                            "meta": dict(match.meta),
                        },
                    )

        return False, "", {}

    def get_virus_list(self) -> list[str]:
        """Get sorted list of detectable virus names.

        Returns:
            Sorted list of virus names
        """
        return sorted(self.virus_names)
