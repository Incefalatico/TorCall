"""
TorCall configuration constants and paths.
"""

import os
import sys

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
APP_NAME = "TorCall"
APP_VERSION = "0.1.0"

# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------
APP_DATA_DIR = os.path.join(os.getenv("APPDATA", os.path.expanduser("~")), APP_NAME)
TOR_DATA_DIR = os.path.join(APP_DATA_DIR, "tor_data")
IDENTITY_DIR = os.path.join(APP_DATA_DIR, "identity")
LOG_DIR = os.path.join(APP_DATA_DIR, "logs")

# Ensure critical directories exist
for _d in (APP_DATA_DIR, TOR_DATA_DIR, IDENTITY_DIR, LOG_DIR):
    os.makedirs(_d, exist_ok=True)

# ---------------------------------------------------------------------------
# Tor
# ---------------------------------------------------------------------------
# Ports are overridable via environment variables so TorCall does not clash
# with a system Tor already bound to the default 9050/9051.
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = int(os.getenv("TORCALL_SOCKS_PORT", "9150"))
TOR_CONTROL_PORT = int(os.getenv("TORCALL_CONTROL_PORT", "9151"))

# Resolve path to bundled tor.exe (works in dev and PyInstaller)
def _resource_path(relative: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    return os.path.join(base, relative)

TOR_BINARY = _resource_path(os.path.join("tor", "tor.exe"))

# ---------------------------------------------------------------------------
# Native libraries
# ---------------------------------------------------------------------------
# Directory holding bundled native libraries (e.g. the Opus codec DLL).
# Resolved the same way as the Tor binary so it works in dev and when
# frozen with PyInstaller.
NATIVE_LIB_DIR = _resource_path("lib")

# ---------------------------------------------------------------------------
# Hidden Service
# ---------------------------------------------------------------------------
HIDDEN_SERVICE_LOCAL_PORT = 7890  # Local TCP port the app listens on
HIDDEN_SERVICE_REMOTE_PORT = 7890  # Port exposed via .onion

# Identity persistence file
IDENTITY_KEY_FILE = os.path.join(IDENTITY_DIR, "hs_key")
IDENTITY_ADDR_FILE = os.path.join(IDENTITY_DIR, "hs_address")
# Long-term identity signing key (Ed25519), encrypted at rest when a
# passphrase is configured.
IDENTITY_SIGN_FILE = os.path.join(IDENTITY_DIR, "id_ed25519")
# Pinned contacts (trust-on-first-use), encrypted at rest.
CONTACTS_FILE = os.path.join(IDENTITY_DIR, "contacts")

# Runtime override for the at-rest passphrase (set via the startup dialog).
# None means "not set" → fall back to the TORCALL_PASSPHRASE env var.
_RUNTIME_PASSPHRASE: "str | None" = None


def get_passphrase() -> str:
    """Return the at-rest encryption passphrase, or empty string if unset.

    The passphrase is resolved in this order:

    1. A runtime override set via :func:`set_passphrase` (e.g. from the
       startup dialog).
    2. The ``TORCALL_PASSPHRASE`` environment variable.

    When empty, secrets fall back to plaintext storage (with a warning) so
    the app keeps working, but users are strongly encouraged to set one.
    """
    if _RUNTIME_PASSPHRASE is not None:
        return _RUNTIME_PASSPHRASE
    return os.getenv("TORCALL_PASSPHRASE", "")


def set_passphrase(passphrase: str) -> None:
    """Set the at-rest encryption passphrase for the current process.

    This takes precedence over the ``TORCALL_PASSPHRASE`` environment
    variable and is used by the startup dialog so the user can supply a
    passphrase without touching environment variables.  Pass an empty
    string to explicitly opt out of encryption for this session.
    """
    global _RUNTIME_PASSPHRASE
    _RUNTIME_PASSPHRASE = passphrase

# ---------------------------------------------------------------------------
# Audio
# ---------------------------------------------------------------------------
SAMPLE_RATE = 48000       # Hz — Opus native rate
CHANNELS = 1              # Mono
FRAME_SIZE = 960           # 20 ms at 48 kHz
AUDIO_DTYPE = "int16"
OPUS_APPLICATION = "voip"  # "voip" | "audio" | "restricted_lowdelay"
OPUS_BITRATE = 24000       # bps (range: 16 000 – 32 000 for voice)

# Jitter buffer
JITTER_BUFFER_INITIAL_MS = 60
JITTER_BUFFER_MIN_MS = 40
JITTER_BUFFER_MAX_MS = 200

# ---------------------------------------------------------------------------
# Network / Protocol
# ---------------------------------------------------------------------------
TCP_BUFFER_SIZE = 4096
CALL_TIMEOUT_S = 60        # Seconds to wait for the callee to answer
PING_INTERVAL_S = 15       # Seconds between keep-alive pings
PING_TIMEOUT_S = 45        # Consider peer dead after this silence

# Auto-reconnect: when a Tor circuit dies mid-call the connection drops even
# though both parties are still online.  The *caller* (who knows the peer's
# .onion address) automatically re-dials a few times before giving up.  The
# callee cannot re-dial — it has no address to call back.
RECONNECT_MAX_ATTEMPTS = int(os.getenv("TORCALL_RECONNECT_ATTEMPTS", "3"))
RECONNECT_DELAY_MS = 1500  # Pause before each re-dial attempt

# ---------------------------------------------------------------------------
# Traffic-analysis resistance
# ---------------------------------------------------------------------------
# Opus is variable-bitrate: louder/active speech produces bigger frames than
# silence, so raw packet sizes leak *when* someone is talking even though the
# content is encrypted.  We pad every audio plaintext up to a multiple of
# TRAFFIC_PAD_BLOCK bytes so all frames quantise to the same handful of sizes.
TRAFFIC_PAD_BLOCK = 256
# When enabled, audio is transmitted at a fixed cadence (one frame every
# FRAME_SIZE/SAMPLE_RATE seconds) and silence frames are sent during gaps, so
# an observer cannot infer speech timing from packet timing.  Toggle off via
# TORCALL_CONSTANT_RATE=0 to save bandwidth at the cost of timing privacy.
CONSTANT_RATE_SEND = os.getenv("TORCALL_CONSTANT_RATE", "1").lower() not in ("0", "false", "no", "off")

# When enabled, audio playback/transmission is gated until the user has
# explicitly confirmed the Short Authentication String (SAS) matches what the
# peer reads aloud — a verbal defence against a man-in-the-middle that swaps
# the ephemeral keys.  Off by default to keep the call UX frictionless; turn
# on with TORCALL_REQUIRE_SAS=1 for high-assurance use.
REQUIRE_SAS_CONFIRMATION = os.getenv("TORCALL_REQUIRE_SAS", "0").lower() in ("1", "true", "yes", "on")

# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------
X25519_KEY_SIZE = 32        # bytes
AES_NONCE_SIZE = 12         # bytes (96-bit for GCM)
AES_TAG_SIZE = 16           # bytes
