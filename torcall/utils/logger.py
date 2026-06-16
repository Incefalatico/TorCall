"""
TorCall logging setup.

Privacy-first logging: by default nothing is written to disk, because
TorCall log lines would otherwise leave a permanent, plaintext record of
who you called and when — exactly the metadata Tor is meant to hide.

* Console output only, unless a log file is explicitly opted into via the
  ``TORCALL_LOG_FILE=1`` environment variable.
* A scrubbing filter redacts ``.onion`` addresses, IPv4/IPv6 literals and
  hidden-service IDs from every record (message *and* args), on every
  handler, so sensitive identifiers never reach the console or a file.

Usage::

    from torcall.utils.logger import log
    log.info("Something happened")
"""

import logging
import os
import re
from datetime import datetime

from torcall.utils.config import LOG_DIR


# ── Scrubbing ─────────────────────────────────────────────────────────

# v3 onion addresses are 56 base32 chars + ".onion"; also catch the bare
# 56-char service id that stem returns without the suffix.
_ONION_RE = re.compile(r"\b[a-z2-7]{56}(?:\.onion)?\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
# IPv6: either a "::"-compressed form (with optional groups on each side)
# or a run of 3+ colon-separated hextets.  Kept deliberately broad so
# addresses are redacted rather than leaked on a near-miss.
_IPV6_RE = re.compile(
    r"(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4})?"      # leading groups + "::"
    r"(?::[0-9a-f]{1,4}){0,6}"                          # optional trailing groups
    r"|(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{1,4}"             # 3+ explicit groups
    r"|::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}",         # leading "::"
    re.IGNORECASE,
)


def scrub(text: str) -> str:
    """Redact onion addresses, IP literals and service ids from *text*."""
    if not text:
        return text
    text = _ONION_RE.sub("<onion>", text)
    text = _IPV4_RE.sub("<ip>", text)
    text = _IPV6_RE.sub("<ip>", text)
    return text


class _ScrubbingFilter(logging.Filter):
    """Logging filter that redacts sensitive identifiers from each record.

    Both the format string and any positional args are scrubbed *before*
    formatting, so an ``.onion`` passed as ``log.info("to %s", addr)`` is
    redacted just like one embedded directly in the message.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = scrub(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._scrub_arg(v) for k, v in record.args.items()}
            else:
                record.args = tuple(self._scrub_arg(a) for a in record.args)
        return True

    @staticmethod
    def _scrub_arg(value):
        return scrub(value) if isinstance(value, str) else value


def _log_to_file_enabled() -> bool:
    """File logging is opt-in only, via TORCALL_LOG_FILE=1/true/yes/on."""
    return os.getenv("TORCALL_LOG_FILE", "").strip().lower() in ("1", "true", "yes", "on")


def setup_logger(name: str = "torcall", level: int = logging.DEBUG) -> logging.Logger:
    """Create and configure the privacy-aware application logger."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)

    scrubber = _ScrubbingFilter()

    # ── Console handler (always on) ──────────────────────────────────
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(
        logging.Formatter(
            "[%(asctime)s] %(name)s %(levelname)s  %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    console.addFilter(scrubber)
    logger.addHandler(console)

    # ── File handler (opt-in only) ───────────────────────────────────
    if _log_to_file_enabled():
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = os.path.join(LOG_DIR, f"torcall_{today}.log")
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(name)s.%(module)s %(levelname)s  %(message)s"
            )
        )
        file_handler.addFilter(scrubber)
        logger.addHandler(file_handler)
        logger.warning(
            "File logging is ENABLED (TORCALL_LOG_FILE) — logs are scrubbed "
            "but still persist call timing metadata to disk at %s",
            LOG_DIR,
        )

    return logger


# Module-level logger instance — import this everywhere
log = setup_logger()
