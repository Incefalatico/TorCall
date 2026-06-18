"""
TorCall application entry point.

Wires together the Tor manager, audio engine, network server,
call manager, and UI into a single coherent application.

Usage::

    from torcall.app import run
    sys.exit(run())
"""

from __future__ import annotations

import os
import sys

from PySide6.QtWidgets import QApplication, QDialog
from PySide6.QtCore import Qt

from torcall.core.tor_manager import TorManager, TorStatus
from torcall.core.audio_engine import AudioEngine
from torcall.core.call_manager import CallManager
from torcall.network.server import CallServer
from torcall.ui.main_window import MainWindow
from torcall.utils.config import HIDDEN_SERVICE_LOCAL_PORT, APP_NAME
from torcall.utils.logger import log


class TorCallApp:
    """
    Glue object that owns all subsystems and wires signals.
    """

    def __init__(self, qt_app: QApplication) -> None:
        self._qt_app = qt_app

        log.info("═══ %s starting ═══", APP_NAME)

        # ── Create subsystems ────────────────────────────────────────
        self._tor = TorManager()
        self._audio = AudioEngine()
        self._server = CallServer()
        self._call_mgr = CallManager(self._audio, self._server)
        self._window = MainWindow()

        # ── Wire Tor signals → UI ────────────────────────────────────
        self._tor.status_changed.connect(self._on_tor_status)
        self._tor.bootstrap_progress.connect(self._on_tor_progress)
        self._tor.address_changed.connect(self._on_address_changed)
        self._tor.error_occurred.connect(self._on_tor_error)

        # ── Wire UI signals → Call Manager ───────────────────────────
        self._window.call_requested.connect(self._call_mgr.place_call)
        self._window.call_accepted.connect(self._call_mgr.accept_call)
        self._window.call_rejected.connect(self._call_mgr.reject_call)
        self._window.hangup_requested.connect(self._call_mgr.end_call)
        self._window.mute_toggled.connect(self._call_mgr.set_muted)
        self._window.generate_address_requested.connect(self._tor.regenerate_address)
        self._window.contacts_requested.connect(self._open_contacts)
        self._window.sas_confirmed.connect(self._call_mgr.confirm_sas)

        # ── Wire Call Manager signals → UI ───────────────────────────
        self._call_mgr.state_changed.connect(self._window.set_call_status)
        self._call_mgr.call_started.connect(self._on_call_started)
        self._call_mgr.call_ended.connect(self._on_call_ended)
        self._call_mgr.incoming_call.connect(self._window.show_incoming_call)
        self._call_mgr.sas_ready.connect(self._window.show_sas)
        self._call_mgr.peer_identity.connect(self._window.show_peer_identity)
        self._call_mgr.sas_confirmation_required.connect(self._window.show_sas_confirmation_required)
        self._call_mgr.error.connect(self._on_error)

        # ── Wire Audio level → UI ───────────────────────────────────
        self._audio.level_changed.connect(self._window.update_audio_level)

        # ── Start Tor in background ──────────────────────────────────
        # After Tor is ready, _on_tor_status will start the server + HS
        self._tor.start()

    # ── Tor callbacks ────────────────────────────────────────────────

    def _on_tor_status(self, status: str) -> None:
        if status == TorStatus.CONNECTING:
            self._window.set_tor_status("Connecting to Tor…", 0)
        elif status == TorStatus.READY:
            self._window.set_tor_status("Connected ✓", 100)
            # Start the TCP server and create/restore hidden service
            self._server.start(HIDDEN_SERVICE_LOCAL_PORT)
            self._tor.create_hidden_service()
        elif status == TorStatus.ERROR:
            self._window.set_tor_status("Tor Error ✗", 0)
        else:
            self._window.set_tor_status(status, 0)

    def _on_tor_progress(self, pct: int) -> None:
        self._window.set_tor_status(f"Connecting to Tor… {pct}%", pct)

    def _on_address_changed(self, address: str) -> None:
        self._window.set_address(address)
        # Tell the call manager our own .onion so it can advertise it inside
        # the handshake; otherwise an incoming call would be pinned under the
        # loopback socket address (the 127.0.0.1 contact bug).
        self._call_mgr.set_local_address(address)

    def _on_tor_error(self, msg: str) -> None:
        log.error("Tor error: %s", msg)
        self._window.set_tor_status(f"Error: {msg}", 0)

    # ── Call callbacks ───────────────────────────────────────────────

    def _on_call_started(self, peer: str) -> None:
        self._window.hide_incoming_call()
        self._window.show_call_widget(peer)

    def _on_call_ended(self) -> None:
        self._window.hide_call_widget()
        self._window.hide_incoming_call()

    def _on_error(self, msg: str) -> None:
        log.error("Call error: %s", msg)
        self._window.set_call_status(f"Error: {msg}")

    # ── Address book ─────────────────────────────────────────────────

    def _open_contacts(self) -> None:
        """Open the address book dialog and dial the picked contact."""
        from torcall.ui.contacts_dialog import ContactsDialog

        dialog = ContactsDialog(
            self._call_mgr.list_contacts,
            self._call_mgr.rename_contact,
            self._call_mgr.remove_contact,
            self._window,
        )
        dialog.call_requested.connect(self._window.prefill_call_address)
        dialog.exec()

    # ── Show / Shutdown ──────────────────────────────────────────────

    def show(self) -> None:
        self._window.show()

    def shutdown(self) -> None:
        log.info("Shutting down…")
        self._call_mgr.end_call()
        self._server.stop()
        self._tor.stop()
        log.info("═══ %s stopped ═══", APP_NAME)


def run() -> int:
    """Create and run the TorCall application.  Returns the exit code."""
    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName(APP_NAME)
    qt_app.setStyle("Fusion")  # Required for consistent QSS theming

    # Ask for the at-rest passphrase before any identity is touched, unless
    # one is already provided via the TORCALL_PASSPHRASE environment variable.
    if not os.getenv("TORCALL_PASSPHRASE"):
        from torcall.ui.passphrase_dialog import PassphraseDialog
        from torcall.utils.config import set_passphrase

        dialog = PassphraseDialog()
        if dialog.exec() != QDialog.DialogCode.Accepted:
            log.info("Passphrase dialog cancelled — exiting")
            return 0
        set_passphrase(dialog.passphrase())

    app = TorCallApp(qt_app)
    app.show()

    # Clean shutdown on exit
    qt_app.aboutToQuit.connect(app.shutdown)

    return qt_app.exec()
