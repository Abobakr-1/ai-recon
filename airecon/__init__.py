"""AI RECON - AI-system reconnaissance toolkit for authorized security testing.

Implements the OSAI (OffSec AI-300) Chapter 2 reconnaissance methodology:
passive fingerprinting, active model/RAG/agent probing, and detection-aware
evasion analysis — against AI-enabled applications.

AUTHORIZED USE ONLY. Every active module refuses to run without an explicit
scope that the target matches. See README.md and `ai-recon scope --help`.

Developed by: AboBakr Mohamed
"""

__version__ = "1.1.0"
__author__ = "AboBakr Mohamed"
__display_name__ = "AI RECON"

# --------------------------------------------------------------------------- #
# Banner. The bold block art below is generated so that every row is exactly
# the same width, so it can never drift out of alignment. A pure-ASCII version
# is used automatically on terminals that cannot encode the box-drawing glyphs.
# --------------------------------------------------------------------------- #
BANNER_BOLD = """
 █████╗ ██╗   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██║   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████║██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██║██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
        AI RECON  -  AI-System Reconnaissance
        Developed by: AboBakr Mohamed
        Authorized testing only
"""

BANNER_ASCII = r"""
    _      ___       ____   _____   ____   ___   _   _
   / \    |_ _|     |  _ \ | ____| / ___| / _ \ | \ | |
  / _ \    | |      | |_) ||  _|  | |    | | | ||  \| |
 / ___ \   | |      |  _ < | |___ | |___ | |_| || |\  |
/_/   \_\ |___|     |_| \_\|_____| \____| \___/ |_| \_|
        AI RECON  -  AI-System Reconnaissance
        Developed by: AboBakr Mohamed
        Authorized testing only
"""


def _can_encode(text: str, encoding: str) -> bool:
    try:
        text.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def banner(stream=None) -> str:
    """Return the bold banner when the output stream can render it, else ASCII."""
    import sys
    stream = stream if stream is not None else sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    return BANNER_BOLD if _can_encode(BANNER_BOLD, encoding) else BANNER_ASCII


BANNER = BANNER_BOLD  # default; the CLI calls banner() for encoding awareness
