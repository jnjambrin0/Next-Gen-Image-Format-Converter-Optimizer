"""
Productivity features for the CLI
Advanced features for power users including autocomplete, profiles, watch mode, and macros
"""

from .autocomplete import AutocompleteEngine
from .dry_run import DryRunSimulator
from .formatters import OutputFormatter
from .fuzzy_search import FuzzySearcher
from .macros import MacroManager
from .profiles import ProfileManager
from .shell_integration import ShellIntegrator
from .watcher import DirectoryWatcher

__all__ = [
    "AutocompleteEngine",
    "FuzzySearcher",
    "ProfileManager",
    "ShellIntegrator",
    "DirectoryWatcher",
    "DryRunSimulator",
    "OutputFormatter",
    "MacroManager",
]
