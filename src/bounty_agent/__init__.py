"""bounty-agent: responsible bug bounty research toolkit."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("bounty-agent")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
