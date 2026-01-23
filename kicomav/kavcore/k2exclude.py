# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Exclusion Rules Module

This module provides file exclusion functionality for the scanner:
- Path-based exclusion (directories and files)
- Extension-based exclusion
- Glob pattern matching
- File size limits

Usage:
    from kicomav.kavcore.k2exclude import ExclusionRule

    rule = ExclusionRule()
    rule.load_from_file(".kicomav-ignore")
    rule.add_pattern("*.log")
    rule.add_extension("tmp")
    rule.set_max_size("100MB")

    if rule.should_exclude("/path/to/file.log", filesize=1024):
        print("File excluded")
"""

import os
import fnmatch
import re
from pathlib import Path
from typing import List, Optional, Set


class ExclusionRule:
    """File exclusion rule matcher."""

    # Size unit multipliers
    SIZE_UNITS = {
        "B": 1,
        "KB": 1024,
        "MB": 1024 * 1024,
        "GB": 1024 * 1024 * 1024,
    }

    def __init__(self):
        self.patterns: List[str] = []  # glob patterns (e.g., "*.log", "node_modules/**")
        self.extensions: Set[str] = set()  # file extensions (e.g., "log", "tmp")
        self.paths: List[str] = []  # absolute/relative paths to exclude
        self.max_size: Optional[int] = None  # max file size in bytes
        self._compiled_patterns: List[re.Pattern] = []

    def load_from_file(self, filepath: str) -> bool:
        """Load exclusion rules from a .kicomav-ignore file.

        File format (similar to .gitignore):
            # Comment line
            *.log           # Exclude all .log files
            /tmp/           # Exclude /tmp directory
            node_modules/   # Exclude node_modules anywhere
            >100MB          # Exclude files larger than 100MB

        Args:
            filepath: Path to the exclusion rules file

        Returns:
            True if file was loaded successfully, False otherwise
        """
        if not os.path.isfile(filepath):
            return False

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    # Remove inline comments
                    if " #" in line:
                        line = line.split(" #")[0].strip()

                    # Parse the rule
                    self._parse_rule(line)

            self._compile_patterns()
            return True

        except (IOError, OSError):
            return False

    def _parse_rule(self, rule: str) -> None:
        """Parse a single exclusion rule.

        Args:
            rule: Rule string to parse
        """
        # File size rule (e.g., ">100MB", "< 50 KB")
        if rule.startswith(">") or rule.startswith("<"):
            size_str = rule[1:].strip()
            size_bytes = self._parse_size(size_str)
            if size_bytes is not None:
                if rule.startswith(">"):
                    self.max_size = size_bytes
            return

        # Extension rule (e.g., "*.log" -> extract "log")
        if rule.startswith("*.") and "/" not in rule and "\\" not in rule:
            ext = rule[2:].lower()
            if ext and not any(c in ext for c in "*?[]"):
                self.extensions.add(ext)
                return

        # Directory/path rule (ends with /)
        if rule.endswith("/") or rule.endswith("\\"):
            self.paths.append(rule.rstrip("/\\"))
            return

        # General glob pattern
        self.patterns.append(rule)

    def _parse_size(self, size_str: str) -> Optional[int]:
        """Parse a size string like '100MB' into bytes.

        Args:
            size_str: Size string (e.g., "100MB", "1GB", "500KB")

        Returns:
            Size in bytes, or None if parsing failed
        """
        size_str = size_str.strip().upper()

        # Try to match number + unit
        match = re.match(r"^(\d+(?:\.\d+)?)\s*(B|KB|MB|GB)?$", size_str)
        if not match:
            return None

        number = float(match.group(1))
        unit = match.group(2) or "B"

        return int(number * self.SIZE_UNITS.get(unit, 1))

    def _compile_patterns(self) -> None:
        """Compile glob patterns to regex for faster matching."""
        self._compiled_patterns = []
        for pattern in self.patterns:
            # Convert glob pattern to regex
            regex = self._glob_to_regex(pattern)
            try:
                self._compiled_patterns.append(re.compile(regex, re.IGNORECASE))
            except re.error:
                pass  # Skip invalid patterns

    def _glob_to_regex(self, pattern: str) -> str:
        """Convert a glob pattern to a regex pattern.

        Args:
            pattern: Glob pattern (e.g., "*.log", "**/*.tmp")

        Returns:
            Regex pattern string
        """
        # Normalize path separators
        pattern = pattern.replace("\\", "/")

        # Escape special regex characters except glob wildcards
        result = ""
        i = 0
        while i < len(pattern):
            c = pattern[i]
            if c == "*":
                if i + 1 < len(pattern) and pattern[i + 1] == "*":
                    # ** matches any path
                    result += ".*"
                    i += 1
                else:
                    # * matches anything except path separator
                    result += "[^/\\\\]*"
            elif c == "?":
                result += "[^/\\\\]"
            elif c == "[":
                # Character class - find matching ]
                j = i + 1
                while j < len(pattern) and pattern[j] != "]":
                    j += 1
                result += pattern[i : j + 1]
                i = j
            elif c in ".^$+{}|()":
                result += "\\" + c
            else:
                result += c
            i += 1

        return f"(?:^|[/\\\\]){result}$"

    def add_pattern(self, pattern: str) -> None:
        """Add a glob pattern to exclude.

        Args:
            pattern: Glob pattern (e.g., "*.log", "node_modules/**")
        """
        self._parse_rule(pattern)
        self._compile_patterns()

    def add_patterns(self, patterns: List[str]) -> None:
        """Add multiple glob patterns to exclude.

        Args:
            patterns: List of glob patterns
        """
        for pattern in patterns:
            self._parse_rule(pattern)
        self._compile_patterns()

    def add_extension(self, ext: str) -> None:
        """Add a file extension to exclude.

        Args:
            ext: Extension without dot (e.g., "log", "tmp")
        """
        self.extensions.add(ext.lower().lstrip("."))

    def add_extensions(self, extensions: List[str]) -> None:
        """Add multiple file extensions to exclude.

        Args:
            extensions: List of extensions (e.g., ["log", "tmp"])
        """
        for ext in extensions:
            self.add_extension(ext)

    def add_path(self, path: str) -> None:
        """Add a path to exclude.

        Args:
            path: Directory or file path to exclude
        """
        self.paths.append(path.rstrip("/\\"))

    def set_max_size(self, size: str) -> bool:
        """Set maximum file size to scan.

        Args:
            size: Size string (e.g., "100MB", "1GB")

        Returns:
            True if size was set successfully
        """
        size_bytes = self._parse_size(size)
        if size_bytes is not None:
            self.max_size = size_bytes
            return True
        return False

    def set_max_size_bytes(self, size_bytes: int) -> None:
        """Set maximum file size in bytes.

        Args:
            size_bytes: Size in bytes
        """
        self.max_size = size_bytes

    def should_exclude(self, filepath: str, filesize: Optional[int] = None) -> bool:
        """Check if a file should be excluded from scanning.

        Args:
            filepath: Path to the file
            filesize: File size in bytes (optional, will be read if not provided)

        Returns:
            True if the file should be excluded
        """
        # Normalize path
        filepath_normalized = filepath.replace("\\", "/")
        filepath_lower = filepath_normalized.lower()

        # Check file size
        if self.max_size is not None:
            if filesize is None:
                try:
                    filesize = os.path.getsize(filepath)
                except OSError:
                    pass

            if filesize is not None and filesize > self.max_size:
                return True

        # Check extension
        if self.extensions:
            ext = os.path.splitext(filepath_lower)[1].lstrip(".")
            if ext in self.extensions:
                return True

        # Check paths
        for excl_path in self.paths:
            excl_normalized = excl_path.replace("\\", "/").lower()
            # Check if the excluded path is in the filepath
            if excl_normalized in filepath_lower:
                return True
            # Check directory match
            if f"/{excl_normalized}/" in f"/{filepath_lower}/":
                return True

        # Check compiled patterns
        for pattern in self._compiled_patterns:
            if pattern.search(filepath_normalized):
                return True

        return False

    def get_summary(self) -> dict:
        """Get a summary of the exclusion rules.

        Returns:
            Dictionary with rule counts and details
        """
        return {
            "patterns": len(self.patterns),
            "extensions": list(self.extensions),
            "paths": len(self.paths),
            "max_size": self.max_size,
            "max_size_str": self._format_size(self.max_size) if self.max_size else None,
        }

    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human-readable string.

        Args:
            size_bytes: Size in bytes

        Returns:
            Human-readable size string
        """
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f}TB"

    def is_empty(self) -> bool:
        """Check if no exclusion rules are defined.

        Returns:
            True if no rules are defined
        """
        return not self.patterns and not self.extensions and not self.paths and self.max_size is None

    def clear(self) -> None:
        """Clear all exclusion rules."""
        self.patterns.clear()
        self.extensions.clear()
        self.paths.clear()
        self.max_size = None
        self._compiled_patterns.clear()


def find_ignore_file(start_path: str, filename: str = ".kicomav-ignore") -> Optional[str]:
    """Find a .kicomav-ignore file starting from the given path.

    Searches in the following order:
    1. start_path directory (if file) or start_path itself (if directory)
    2. Parent directories up to root
    3. User home directory (~/.kicomav/.kicomav-ignore)

    Args:
        start_path: Starting path for search
        filename: Name of the ignore file

    Returns:
        Path to the ignore file, or None if not found
    """
    # Start from the directory containing the path
    if os.path.isfile(start_path):
        current = os.path.dirname(os.path.abspath(start_path))
    else:
        current = os.path.abspath(start_path)

    # Search up the directory tree
    while True:
        ignore_path = os.path.join(current, filename)
        if os.path.isfile(ignore_path):
            return ignore_path

        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent

    # Check user home directory
    home_ignore = os.path.join(os.path.expanduser("~"), ".kicomav", filename)
    if os.path.isfile(home_ignore):
        return home_ignore

    return None


def create_exclusion_rule(
    patterns: Optional[List[str]] = None,
    extensions: Optional[List[str]] = None,
    paths: Optional[List[str]] = None,
    max_size: Optional[str] = None,
    ignore_file: Optional[str] = None,
) -> ExclusionRule:
    """Factory function to create an ExclusionRule with common options.

    Args:
        patterns: List of glob patterns
        extensions: List of file extensions
        paths: List of paths to exclude
        max_size: Maximum file size string (e.g., "100MB")
        ignore_file: Path to ignore file to load

    Returns:
        Configured ExclusionRule instance
    """
    rule = ExclusionRule()

    if ignore_file:
        rule.load_from_file(ignore_file)

    if patterns:
        rule.add_patterns(patterns)

    if extensions:
        rule.add_extensions(extensions)

    if paths:
        for path in paths:
            rule.add_path(path)

    if max_size:
        rule.set_max_size(max_size)

    return rule
