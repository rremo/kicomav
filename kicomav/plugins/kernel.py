# -*- coding:utf-8 -*-
# Made by Kei Choi(hanul93@gmail.com)

"""
KicomAV Kernel Plugin Interface

This module defines the base classes and constants for KicomAV plugins.
"""

from abc import ABCMeta, abstractmethod
from typing import Dict, Any, Optional


# Malware scan result
NOT_FOUND: int = 0
INFECTED: int = 1
SUSPECT: int = 2
WARNING: int = 3
IDENTIFIED: int = 4
ERROR: int = 99


# Disinfect method for malware
DISINFECT_NONE: int = -1
DISINFECT_DELETE: int = 0x8000
DISINFECT_MALWARE: int = 0x80000000  # Specific malware disinfection function setting


# Clean Malware for Compressed Files
MASTER_IGNORE: int = 0  # it is not currently supported
MASTER_PACK: int = 1  # Top-level file compression (reconstruction), can handle mkarc function
MASTER_DELETE: int = 2  # Delete top-level file


# Engine type
ARCHIVE_ENGINE: int = 80

# Type aliases for plugin info
PluginInfo = Dict[str, Any]
RulesPaths = Dict[str, str]


# -------------------------------------------------------------------------
# class PluginsMain
# -------------------------------------------------------------------------
class PluginsMain(metaclass=ABCMeta):
    """Base class for all KicomAV plugins."""

    # ---------------------------------------------------------------------
    # init(self, rules_paths, verbose)
    # Initialize the plug-in engine
    # input  : rules_paths - Dict with rule paths {"system": "/path", "user": "/path"}
    #          verbose     - verbose (True or False)
    # return : 0 - success, Nonzero - fail
    # ---------------------------------------------------------------------
    def init(self, rules_paths: Optional[RulesPaths] = None, verbose: bool = False) -> int:
        return 0

    # ---------------------------------------------------------------------
    # uninit(self)
    # Quit the plug-in engine
    # return : 0 - success, Nonzero - fail
    # ---------------------------------------------------------------------
    def uninit(self) -> int:
        return 0

    # ---------------------------------------------------------------------
    # getinfo(self)
    # Provides information about the plug-in engine. (author, version, ...)
    # return : Plug-in information
    # ---------------------------------------------------------------------
    @abstractmethod
    def getinfo(self) -> PluginInfo:
        return {}


# -------------------------------------------------------------------------
# class KavMain
# -------------------------------------------------------------------------
class KavMain(PluginsMain):
    """KicomAV Kernel plugin implementation."""

    # ---------------------------------------------------------------------
    # getinfo(self)
    # Provides information about the plug-in engine. (author, version, ...)
    # return : Plug-in information
    # ---------------------------------------------------------------------
    def getinfo(self) -> PluginInfo:
        return {
            "author": "Kei Choi",
            "version": "1.0",
            "title": "KicomAV Kernel",
            "kmd_name": "kernel",
        }
