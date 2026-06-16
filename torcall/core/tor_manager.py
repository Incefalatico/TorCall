"""
TorCall Tor process manager.

Manages the lifecycle of an embedded ``tor.exe`` process and the
creation / persistence of Tor hidden services via the ``stem`` library.
"""

from __future__ import annotations

import os
import threading
from typing import Optional

from PySide6.QtCore import QObject, QThread, Signal, Slot

from torcall.utils.config import (
    TOR_BINARY,
    TOR_CONTROL_PORT,
    TOR_DATA_DIR,
    TOR_SOCKS_PORT,
    HIDDEN_SERVICE_LOCAL_PORT,
    HIDDEN_SERVICE_REMOTE_PORT,
    IDENTITY_KEY_FILE,
    IDENTITY_ADDR_FILE,
    get_passphrase,
)
from torcall.core.crypto import encrypt_at_rest, decrypt_at_rest, is_vault_blob
from torcall.utils.logger import log

try:
    from stem.process import launch_tor_with_config
    from stem.control import Controller
    _STEM_AVAILABLE = True
except ImportError:
    _STEM_AVAILABLE = False
    log.warning("stem library not found — Tor features will be unavailable")


class TorStatus:
    """Possible states of the Tor subsystem."""
    IDLE = "idle"
    CONNECTING = "connecting"
    READY = "ready"
    ERROR = "error"


# ── Background worker ────────────────────────────────────────────────

class _TorWorker(QObject):
    """Runs Tor operations off the main (UI) thread."""

    status_changed = Signal(str)
    bootstrap_progress = Signal(int)
    address_changed = Signal(str)
    error_occurred = Signal(str)
    started = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._tor_process = None
        self._controller: Optional[Controller] = None
        self._onion_address: Optional[str] = None
        self._service_id: Optional[str] = None
        self._stop_event = threading.Event()
        self._addr_lock = threading.Lock()  # guards _onion_address cross-thread

    def get_onion_address(self) -> Optional[str]:
        """Thread-safe read of the current .onion address."""
        with self._addr_lock:
            return self._onion_address

    # ── Tor process lifecycle ────────────────────────────────────────

    @Slot()
    def start_tor(self) -> None:
        """Launch the Tor process and wait for bootstrap."""
        if not _STEM_AVAILABLE:
            self.error_occurred.emit("stem library is not installed")
            self.status_changed.emit(TorStatus.ERROR)
            return

        if not os.path.isfile(TOR_BINARY):
            self.error_occurred.emit(f"tor.exe not found at {TOR_BINARY}")
            self.status_changed.emit(TorStatus.ERROR)
            return

        self.status_changed.emit(TorStatus.CONNECTING)

        def _bootstrap_handler(line: str) -> None:
            """Parse Tor bootstrap messages for progress %."""
            if "Bootstrapped" in line:
                try:
                    pct = int(line.split("Bootstrapped")[1].split("%")[0].strip())
                    self.bootstrap_progress.emit(pct)
                except (IndexError, ValueError):
                    pass

        try:
            log.info("Starting Tor process …")
            self._tor_process = launch_tor_with_config(
                tor_cmd=TOR_BINARY,
                config={
                    "SocksPort": str(TOR_SOCKS_PORT),
                    "ControlPort": str(TOR_CONTROL_PORT),
                    "CookieAuthentication": "1",
                    "DataDirectory": TOR_DATA_DIR,
                    "Log": "NOTICE stdout",
                },
                take_ownership=True,
                init_msg_handler=_bootstrap_handler,
            )

            # Connect the controller
            self._controller = Controller.from_port(port=TOR_CONTROL_PORT)
            self._controller.authenticate()

            self.bootstrap_progress.emit(100)
            self.status_changed.emit(TorStatus.READY)
            self.started.emit()
            log.info("Tor is ready (SOCKS %d, Control %d)", TOR_SOCKS_PORT, TOR_CONTROL_PORT)

        except Exception as exc:
            log.exception("Failed to start Tor")
            self.error_occurred.emit(str(exc))
            self.status_changed.emit(TorStatus.ERROR)

    def stop_tor(self) -> None:
        """Terminate the Tor process and clean up."""
        self._stop_event.set()
        try:
            if self._controller:
                self._controller.close()
                self._controller = None
            if self._tor_process:
                self._tor_process.kill()
                self._tor_process = None
            log.info("Tor process stopped")
        except Exception:
            log.exception("Error stopping Tor")
        finally:
            self.status_changed.emit(TorStatus.IDLE)

    # ── Hidden service management ────────────────────────────────────

    def create_hidden_service(self, key_content: Optional[str] = None,
                              key_type: str = "ED25519-V3") -> None:
        """
        Create an ephemeral hidden service.

        If *key_content* is provided the same .onion address is restored,
        otherwise a fresh keypair is generated.
        """
        if not self._controller:
            self.error_occurred.emit("Tor controller not connected")
            return

        try:
            port_mapping = {HIDDEN_SERVICE_REMOTE_PORT: HIDDEN_SERVICE_LOCAL_PORT}

            if key_content:
                response = self._controller.create_ephemeral_hidden_service(
                    port_mapping,
                    key_type=key_type,
                    key_content=key_content,
                    await_publication=True,
                )
            else:
                response = self._controller.create_ephemeral_hidden_service(
                    port_mapping,
                    key_type="NEW",
                    key_content="ED25519-V3",
                    await_publication=True,
                )

            self._service_id = response.service_id
            with self._addr_lock:
                self._onion_address = f"{response.service_id}.onion"

            # Tor only returns the private key when a NEW key is generated.
            # When restoring an existing key (key_content provided) the
            # response carries no key material, so we must NOT overwrite the
            # saved identity with empty values.
            if response.private_key_type and response.private_key:
                self._save_identity(
                    response.private_key_type,
                    response.private_key,
                )

            self.address_changed.emit(self._onion_address)
            log.info("Hidden service ready: %s", self._onion_address)

        except Exception as exc:
            log.exception("Failed to create hidden service")
            self.error_occurred.emit(str(exc))

    @Slot()
    def regenerate_address(self) -> None:
        """Remove current hidden service and create a brand-new one."""
        try:
            if self._controller and self._service_id:
                self._controller.remove_ephemeral_hidden_service(self._service_id)
                log.info("Removed old hidden service %s", self._service_id)
        except Exception:
            log.exception("Error removing old hidden service")

        self._service_id = None
        with self._addr_lock:
            self._onion_address = None

        # Remove saved identity
        for f in (IDENTITY_KEY_FILE, IDENTITY_ADDR_FILE):
            try:
                os.remove(f)
            except FileNotFoundError:
                pass

        # Create fresh
        self.create_hidden_service()

    # ── Identity persistence ─────────────────────────────────────────

    def _save_identity(self, key_type: str, key_content: str) -> None:
        """Persist the hidden-service private key to disk.

        When a passphrase is configured (``TORCALL_PASSPHRASE``) the key
        material is encrypted at rest with scrypt + AES-256-GCM, so a copy
        of the identity file alone cannot be used to impersonate this
        ``.onion`` address.  Without a passphrase it falls back to plaintext
        (with a warning) for backward compatibility, relying on OS file
        permissions only.
        """
        payload = f"{key_type}\n{key_content}".encode("utf-8")
        passphrase = get_passphrase()
        try:
            if passphrase:
                blob = encrypt_at_rest(passphrase, payload)
                with open(IDENTITY_KEY_FILE, "wb") as fk:
                    fk.write(blob)
            else:
                log.warning(
                    "No TORCALL_PASSPHRASE set — hidden-service key stored in "
                    "PLAINTEXT. Set a passphrase to encrypt your identity at rest."
                )
                with open(IDENTITY_KEY_FILE, "wb") as fk:
                    fk.write(payload)
            if self._onion_address:
                with open(IDENTITY_ADDR_FILE, "w", encoding="utf-8") as fa:
                    fa.write(self._onion_address)
            log.debug("Identity saved to %s", IDENTITY_KEY_FILE)
        except OSError:
            log.exception("Failed to save identity")

    @Slot()
    def load_identity(self) -> None:
        """Load saved identity and recreate the hidden service."""
        if not os.path.isfile(IDENTITY_KEY_FILE):
            log.info("No saved identity — will generate new address")
            self.create_hidden_service()
            return

        try:
            with open(IDENTITY_KEY_FILE, "rb") as fk:
                raw = fk.read()

            if is_vault_blob(raw):
                passphrase = get_passphrase()
                if not passphrase:
                    log.error(
                        "Identity is encrypted but no TORCALL_PASSPHRASE is set "
                        "— generating a new address instead"
                    )
                    self.create_hidden_service()
                    return
                payload = decrypt_at_rest(passphrase, raw)
            else:
                payload = raw  # legacy plaintext identity

            text = payload.decode("utf-8").strip()
            key_type, key_content = text.split("\n", 1)
            key_type = key_type.strip()
            key_content = key_content.strip()

            # Guard against a corrupted / empty identity file (e.g. one that
            # was accidentally written with placeholder values). Restoring it
            # would make Tor reject the ADD_ONION with "Invalid key type".
            valid_types = {"RSA1024", "ED25519-V3"}
            if key_type not in valid_types or not key_content:
                log.warning(
                    "Saved identity is invalid (type=%r) — generating a new address",
                    key_type,
                )
                self.create_hidden_service()
                return

            log.info("Restoring identity (type=%s)", key_type)
            self.create_hidden_service(key_content=key_content, key_type=key_type)
        except Exception:
            log.exception("Failed to load identity — generating new address")
            self.create_hidden_service()


# ── Public façade (runs on the main thread) ──────────────────────────

class TorManager(QObject):
    """
    High-level Tor manager.

    All heavy operations run in a background :class:`QThread`.
    Connect to the signals to react to state changes from the UI.
    """

    # Re-exported signals from the worker
    status_changed = Signal(str)
    bootstrap_progress = Signal(int)
    address_changed = Signal(str)
    error_occurred = Signal(str)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)

        self._thread = QThread()
        self._worker = _TorWorker()
        self._worker.moveToThread(self._thread)

        # Bridge worker signals → manager signals
        self._worker.status_changed.connect(self.status_changed)
        self._worker.bootstrap_progress.connect(self.bootstrap_progress)
        self._worker.address_changed.connect(self.address_changed)
        self._worker.error_occurred.connect(self.error_occurred)

        self._thread.start()

    # ── Public API (thread-safe via signal/slot queuing) ─────────────

    def start(self) -> None:
        """Launch Tor and create / restore the hidden service."""
        # QMetaObject.invokeMethod runs on the worker's thread
        from PySide6.QtCore import QMetaObject, Qt, Q_ARG
        QMetaObject.invokeMethod(self._worker, "start_tor", Qt.ConnectionType.QueuedConnection)

    def create_hidden_service(self) -> None:
        """Create or restore the hidden service (called after Tor is ready)."""
        from PySide6.QtCore import QMetaObject, Qt
        QMetaObject.invokeMethod(self._worker, "load_identity", Qt.ConnectionType.QueuedConnection)

    def regenerate_address(self) -> None:
        """Generate a brand-new .onion address."""
        from PySide6.QtCore import QMetaObject, Qt
        QMetaObject.invokeMethod(self._worker, "regenerate_address", Qt.ConnectionType.QueuedConnection)

    def stop(self) -> None:
        """Stop Tor and clean up the thread."""
        self._worker.stop_tor()
        self._thread.quit()
        self._thread.wait(5000)
        log.info("TorManager shut down")

    def get_onion_address(self) -> Optional[str]:
        """Return current .onion address (may be None)."""
        return self._worker.get_onion_address()

    def get_socks_port(self) -> int:
        """Return the SOCKS proxy port."""
        return TOR_SOCKS_PORT
