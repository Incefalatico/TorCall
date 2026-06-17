# TorCall — Encrypted Voice Calls over Tor

TorCall is a modern, secure, peer-to-peer desktop application for making encrypted voice calls through the **Tor** network, built with **Python 3.11**, **PySide6 (Qt)** and **Tor Hidden Services**.

It lets users call each other anonymously by simply exchanging ephemeral `.onion` addresses.

> 🔐 **The `.onion` address must be exchanged over an already-encrypted, trusted channel** (Signal, Session, etc.), **not** via plaintext SMS or email. The SAS protects against an active man-in-the-middle, but sharing the address over an insecure channel exposes who you are communicating with.

---

## 🔒 Security and Design Features

* **Anonymity**: All connections are routed through the Tor network. The location and IP address of both caller and callee are hidden using Tor's onion routing.
* **End-to-End Encryption (E2EE)**:
  * **Key Exchange**: An ephemeral **X25519** (ECDH) key pair is generated for every single call.
  * **Key Derivation**: From the ECDH secret, **two distinct directional keys** are derived via **HKDF-SHA256** (one for the caller→callee stream, one for callee→caller). Using separate keys for each direction avoids AES-GCM nonce reuse, since both peers start their own packet counter from 0.
  * **Encryption**: Audio streams are encrypted packet by packet with **AES-256-GCM** using a unique 12-byte nonce (structured as an 8-byte big-endian monotonic counter padded with zeros).
  * **Anti-replay**: The receiver tracks the last accepted audio sequence and discards duplicate or out-of-order packets; the counter only advances after a successful authenticated decryption.
  * **Anti-MITM verification (SAS)**: The ephemeral X25519 exchange protects against passive eavesdroppers but not against an active man-in-the-middle relaying the handshake. At the start of every call the app shows a **Short Authentication String** (4 words) derived from both peers' public keys: the two parties compare it aloud and, if it doesn't match, the call is compromised and should be closed.
* **Persistent identity and contact recognition**:
  * **Long-term Ed25519 identity**: in addition to the per-call ephemeral keys, each installation generates a persistent **Ed25519** key pair. On every handshake the ephemeral X25519 key is **signed** with the long-term identity, so the peer can verify that whoever controls the `.onion` address also controls the recognized identity.
  * **Contact pinning (Trust-On-First-Use)**: on the first call to an address, the peer's identity is **pinned**. If on a later call the identity associated with that address changes, the app shows an `⚠ IDENTITY CHANGED` warning — exactly like SSH does with host keys — flagging a possible MITM or an identity rotation to verify.
  * **Human-readable fingerprint**: each identity is summarized as a grouped hexadecimal fingerprint (e.g. `a1:b2:c3:…`) shown during the call.
  * **Address book**: pinned contacts can be browsed in an address book where you can **rename** them, copy their address to call them again, or **remove** them. Removal deletes every `.onion` address tied to the same identity (useful if the contact rotated address but kept the key) and is protected by an explicit confirmation.
* **Protection of secrets at rest**:
  * **Passphrase encryption**: the hidden service identity, the Ed25519 identity and the contacts database are encrypted on disk with **scrypt** (passphrase stretching) + **AES-256-GCM** when the `TORCALL_PASSPHRASE` environment variable is set. With no passphrase it falls back to plaintext storage with a warning (for backward compatibility), relying on the operating system's file permissions.
  * **Memory hygiene**: session keys and ephemeral private keys are kept in mutable `bytearray`s and **zeroed** at the end of the call, to reduce the persistence of secrets in memory.
* **Traffic-analysis resistance**:
  * **Block padding**: every encrypted audio frame is padded up to a multiple of `TRAFFIC_PAD_BLOCK` (256 bytes) before encryption, so all packet sizes collapse onto a few fixed values. This hides Opus's variable-bitrate (VBR) signal, which would otherwise reveal *when* someone is speaking even if the content is encrypted.
  * **Constant rate**: in `CONSTANT_RATE_SEND` mode (on by default) audio packets are transmitted at a fixed cadence (one frame every 20 ms) and **silence frames** are sent during gaps, so an observer cannot infer speech timing from packet timing. Can be disabled with `TORCALL_CONSTANT_RATE=0` to save bandwidth at the cost of timing privacy.
* **Log hygiene**:
  * Logs go to **console only** by default (file logging is opt-in via `TORCALL_LOG_FILE=1`) and an automatic filter **scrubs** `.onion` addresses, service ids and IPv4/IPv6 addresses from messages, preventing sensitive data from accidentally ending up in logs.
* **Audio handling**:
  * Real-time microphone capture and playback through the `sounddevice` library running on dedicated background threads.
  * Adaptive **jitter buffer** queue: it pre-buffers up to a *target* depth before releasing audio, raises the target when underruns recur and lowers it cautiously when the link is stable, to absorb latency fluctuations over Tor while keeping latency as low as possible.
  * Audio compression via the **Opus** codec (with automatic fallback to uncompressed PCM if the native DLL library is missing).
* **User experience**:
  * A modern, sleek dark theme in QSS (CSS for Qt) with Tor-style purple accents and a glassmorphism layout.
  * Microphone always active during the call, with a quick button to toggle mute.
  * Procedurally generated ringtone played during incoming-call alerts.
  * One-click address-to-clipboard copy and automatic regeneration of ephemeral hidden service addresses.

---

## 🏗️ Project Architecture

```
TorCall/
├── main.py                    # Application entry point
├── requirements.txt           # Python package dependencies
├── README.md                  # Project documentation (Italian)
│
├── tor/                       # Extracted Tor Expert Bundle binaries
│   └── tor.exe
│
├── torcall/
│   ├── __init__.py
│   ├── app.py                 # Subsystem initialization and coordination
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── audio_engine.py    # Microphone/speaker handling and Opus codec
│   │   ├── crypto.py          # X25519/Ed25519, AES-GCM, at-rest, padding, SAS
│   │   ├── identity.py        # Persistent Ed25519 identity + contact pinning (TOFU)
│   │   ├── tor_manager.py     # Tor process control and hidden service registration
│   │   └── call_manager.py    # State machine (Idle, Dialing, Ringing, InCall)
│   │
│   ├── network/
│   │   ├── __init__.py
│   │   ├── protocol.py        # Binary signaling protocol and audio packets
│   │   ├── server.py          # TCP server listening on the hidden service local port
│   │   └── client.py          # Outbound SOCKS5 connector through the Tor SOCKS proxy
│   │
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── main_window.py     # Main window and ringtone emitter
│   │   ├── call_widget.py     # In-call interface (Timer, Mute, Volume)
│   │   └── styles.py          # Custom QSS stylesheet
│   │
│   └── utils/
│       ├── __init__.py
│       ├── config.py          # Global configuration and application constants
│       └── logger.py          # Thread-safe console and file logging
│
├── tests/
│   ├── test_audio.py          # Tests for jitter buffer and Opus encode/decode
│   ├── test_crypto.py         # Crypto tests: ECDH, AES-GCM, at-rest, Ed25519, padding
│   ├── test_identity.py       # Persistent identity and contact pinning tests (TOFU)
│   ├── test_logger.py         # .onion/IP log scrubbing tests
│   └── test_protocol.py       # Packet serialization and signed handshake tests
│
└── scratch/                   # Utility and verification scripts
    ├── find_tor.py            # Script to locate Tor release directories
    ├── download_tor.py        # Automatic Tor Expert Bundle download
    └── test_tor_bootstrap.py  # Script to manually test Tor bootstrap
```

---

## 🛠️ Key Fixes and Improvements

### Security

1. **Directional keys (AES-GCM nonce reuse fix)**:
   - Previously both peers derived the *same* key and restarted from counter `seq=0`, thus reusing the key+nonce pair for each side's first packet — a catastrophic condition for AES-GCM. Now `crypto.derive_session_keys()` expands the ECDH secret with HKDF to 64 bytes and splits it into a `caller→callee` key and a `callee→caller` key, so the two streams never share the nonce space.
2. **Listening on loopback only**:
   - `server.py` now binds to `127.0.0.1` instead of `0.0.0.0`. Since the hidden service forwards its remote port to the local one, listening on all interfaces exposed the call port to the LAN, allowing connections that bypassed Tor.
3. **Anti-replay protection**:
   - The `CallManager` tracks the last accepted audio sequence and discards duplicate or out-of-order packets. The counter only advances after an authenticated decryption, so a forged sequence cannot poison the anti-replay window.
4. **Anti-MITM verification (SAS)**:
   - At the start of the call a 4-word Short Authentication String is shown, derived from both peers' public keys and role-independent, to be compared aloud to unmask an active man-in-the-middle.
5. **Serialized socket sends**:
   - All `sendall` calls (audio, ping, ACK) go through a single lock-protected helper, preventing concurrent writes from different threads from interleaving bytes and corrupting packet framing.

### Privacy and anonymity

13. **Persistent Ed25519 identity + signed handshake with anti-replay nonce**:
    - Each installation has a long-term Ed25519 identity key that signs the ephemeral X25519 key on every call. The peer verifies the signature and can recognize the same identity across different calls, regardless of the `.onion` address.
    - The v2 handshake includes a **16-byte nonce** (8-byte timestamp + 8 random bytes) covered by the signature: the receiver rejects signatures with a stale (beyond ±120 s) or tampered nonce, preventing the replay of an old handshake. v1 and v2 signatures are not interchangeable.
14. **Contact pinning (TOFU)**:
    - A contact's identity is pinned on first contact and compared on subsequent calls. An identity change for the same address triggers a visible warning (`⚠ IDENTITY CHANGED`), like SSH host keys.
15. **Secrets encrypted at rest**:
    - Hidden service identity, Ed25519 identity and contacts database are encrypted with scrypt + AES-256-GCM when `TORCALL_PASSPHRASE` is set. The current format is self-describing (magic `TCV2`, with the scrypt cost parameter `log2(N)` written in the header and authenticated as associated data), with automatic detection and backward-compatible reading of older `TCV1` blobs and legacy plaintext files.
16. **Memory hygiene**:
    - Session and ephemeral private keys are `bytearray`s zeroed at the end of the call, reducing the persistence of secrets in RAM.
17. **Traffic-analysis resistance**:
    - 256-byte block padding of audio frames (hides Opus's VBR signal) and constant-rate sending with silence frames (hides speech timing).
18. **Log hygiene**:
    - Console-only logs by default (file opt-in via `TORCALL_LOG_FILE`) with automatic scrubbing of `.onion` addresses, service ids and IPs from messages.

### Reliability and correctness

6. **Send pipeline off the UI thread**:
   - Opus encoding, encryption and sending (potentially blocking over Tor) were moved from the GUI thread to a dedicated thread fed by a bounded queue, eliminating interface stalls every 20 ms.
7. **Effective keep-alive watchdog**:
   - `PING_TIMEOUT_S` is now actually enforced: if no traffic arrives from the peer within the threshold, the call is closed even when `sendall` still appears to work, detecting silent peer deaths.
8. **TorManager slots and threading**:
   - The background worker methods (`start_tor`, `regenerate_address`, `load_identity`) in `tor_manager.py` were decorated with PySide6's `@Slot()`. This fixed cross-thread communication issues, letting `QMetaObject.invokeMethod` find and run them correctly via a queued connection (`QueuedConnection`). The `.onion` address is now lock-protected for cross-thread access.
9. **Tor launch API fix**:
   - Replaced `stem.process.launch_tor` with `stem.process.launch_tor_with_config`. The previous function raised a `TypeError` because it did not accept custom configuration dictionaries.
10. **Opus codec fallback**:
    - Modified `audio_engine.py` to catch any generic `Exception` (not just `ImportError`) when importing `opuslib`. On Windows, `opuslib` imports correctly but raises an exception if the native `libopus.dll` is not installed on the system. The app now automatically falls back to uncompressed PCM streaming, avoiding a crash.
11. **SOCKS5 DNS resolution**:
    - Configured the SOCKS5 socket in `client.py` with `rdns=True` (Remote DNS resolution) so that remote `.onion` names are resolved securely by the Tor proxy, preventing accidental local DNS leaks.
12. **Configurable Tor ports**:
    - The SOCKS and Control ports can now be overridden via the `TORCALL_SOCKS_PORT` and `TORCALL_CONTROL_PORT` environment variables (default `9150`/`9151`), to avoid clashing with a system Tor already bound to the standard `9050`/`9051` ports.

---

## 🚀 Usage Guide

### 1. Environment Setup
Create a Python virtual environment and install the required dependencies:
```powershell
# Create the virtual environment
python -m venv .venv

# Activate the virtual environment
.venv\Scripts\activate

# Install the requirements
pip install -r requirements.txt
```

### 2. Download the Tor Binaries
Run the script to automatically download and extract the Tor Expert Bundle for Windows into the project folder:
```powershell
python scratch/download_tor.py
```
This extracts `tor.exe` into the `tor/` directory.

### 3. Run the Unit Tests
Make sure the `pytest` test library is installed and run the automated test suite:
```powershell
pip install pytest
python -m pytest tests/ -v
```

### 4. Launch the Application
Start TorCall:
```powershell
python main.py
```

> **Custom Tor ports (optional)** — If you already have a system Tor running on the standard ports, set alternative ports before launching:
> ```powershell
> $env:TORCALL_SOCKS_PORT = "9150"
> $env:TORCALL_CONTROL_PORT = "9151"
> python main.py
> ```

### 5. Verify the Call Identity (SAS)
As soon as the call is established, both parties see a **4-word** string (Short Authentication String) under the "Verify aloud" label. Read it aloud to each other: if the words match on both sides the connection is authentic end-to-end; if they **don't** match, someone might be intercepting the call (man-in-the-middle) and you should hang up.

Below the SAS the app also shows the contact's **identity status**:
- `🔑 New contact pinned` — first contact with that address, identity just pinned.
- `✓ Known contact` — the identity matches the previously pinned one.
- `⚠ IDENTITY CHANGED` — the identity differs from the expected one: possible MITM or key rotation, to verify before trusting.

### 6. Privacy Environment Variables (optional)
TorCall works with no configuration, but some environment variables strengthen privacy:

```powershell
# Encrypt at rest the hidden service identity, Ed25519 identity and contacts
$env:TORCALL_PASSPHRASE = "a-strong-passphrase"

# Disable constant rate (saves bandwidth, reduces timing privacy)
$env:TORCALL_CONSTANT_RATE = "0"

# Enable file logging (off by default)
$env:TORCALL_LOG_FILE = "1"

# Require manual confirmation of the SAS words before enabling audio
# (anti-MITM: no audio flows until both sides confirm).
# Off by default for convenience, but RECOMMENDED to always enable it if
# security takes priority over convenience.
$env:TORCALL_REQUIRE_SAS = "1"

# Number of automatic reconnection attempts on the caller side if the
# connection drops during the call (default 3; 0 disables reconnection).
$env:TORCALL_RECONNECT_ATTEMPTS = "3"

python main.py
```

> ⚠️ **Important**: without `TORCALL_PASSPHRASE` the secrets are stored in plaintext on disk (with a warning in the logs), relying only on the operating system's file permissions. Set a passphrase to encrypt them at rest.

---

## 📋 Signaling Protocol and Data Details

TorCall communicates through a lightweight custom binary protocol. Each packet consists of a **fixed 7-byte header** followed by a variable-length payload:

```
┌──────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ Message Type     │ Sequence Number  │ Payload          │ Payload ...      │
│ (1 Byte)         │ (4 Bytes)        │ Length (2 Bytes) │                  │
└──────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

### Protocol Messages
- **`CALL_REQUEST` (0x01)**: Handshake start. The payload is a *signed handshake*. In the current format (v2, **144 bytes**): ephemeral X25519 public key (32 bytes) + Ed25519 public identity (32 bytes) + Ed25519 signature (64 bytes) + anti-replay nonce (16 bytes). The signature covers nonce + ephemeral key. The 128-byte v1 format (without nonce) and the 32-byte legacy format (ephemeral key only, no identity) are also accepted for backward compatibility.
- **`CALL_ACCEPT` (0x02)**: Positive response to the call. Same signed handshake format as `CALL_REQUEST`.
- **`CALL_REJECT` (0x03)**: Call rejection (or a busy signal if the recipient is already in another call).
- **`AUDIO_DATA` (0x10)**: Real-time encrypted audio packet. The payload is structured as `[12B GCM nonce] + [AES-GCM ciphertext]`. The encrypted plaintext is a *padded* Opus frame (2-byte length prefix + data + zero padding up to a multiple of 256 bytes) to resist traffic analysis.
- **`CALL_END` (0x20)**: End-of-call signal (hang up).
- **`CALL_END_ACK` (0x21)**: End-of-call acknowledgment.
- **`PING` (0x30) / `PONG` (0x31)**: Keep-alive packets sent every 15 seconds to keep the Tor network's TCP circuits alive.

---

## ⚠️ Known Limitations

For honesty and transparency, here are the project's current limitations:

- **Windows only**: the Tor binary path is fixed to `tor/tor.exe` and the setup scripts download native Windows builds (Tor Expert Bundle and libopus MSYS2). On Linux/macOS startup fails with `tor.exe not found` until the Tor binary is made platform-dependent — work not yet implemented or tested.
- **Tor latency**: routing through multiple relays adds variable latency. Under good network conditions the conversation is smooth, but on slow or congested circuits the latency can make the conversation feel unnatural. The adaptive jitter buffer mitigates the problem but doesn't eliminate it.
- **No pluggable transport support**: on networks that block or censor Tor (DPI, blocking of known relays) TorCall has no bridges or pluggable transports (obfs4, Snowflake, etc.), so it may fail to start the circuit.
- **Handshake replay window**: the freshness nonce limits handshake replay to a ±120-second window (tolerance for clock skew), it does not eliminate it entirely.
- **Manual anti-MITM verification**: security against an active man-in-the-middle depends on users actually comparing the SAS aloud. If the verification is skipped, an active MITM is not detected.
