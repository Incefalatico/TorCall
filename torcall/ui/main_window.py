"""
TorCall — main application window.

Assembles the full UI: title bar, Tor connection status, address
management, call input, status display, and the in-call widget.

Also provides an incoming-call overlay with a pulsing animation and
a programmatically-generated ringtone.
"""

from __future__ import annotations

import math
import os
import struct
import wave

from PySide6.QtCore import (
    QPropertyAnimation,
    QEasingCurve,
    QSize,
    QTimer,
    Qt,
    Signal,
)
from PySide6.QtGui import QClipboard, QGuiApplication, QIcon, QKeySequence, QShortcut
from PySide6.QtMultimedia import QSoundEffect
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QGraphicsOpacityEffect,
)

from torcall.ui.call_widget import CallWidget
from torcall.ui.styles import DARK_STYLESHEET, Colors
from torcall.utils.config import APP_DATA_DIR, APP_NAME, APP_VERSION
from torcall.utils.logger import log


# ──────────────────────────────────────────────────────────────────────────────
# Ringtone generation helper
# ──────────────────────────────────────────────────────────────────────────────

_RINGTONE_PATH = os.path.join(APP_DATA_DIR, "ringtone.wav")


def _ensure_ringtone() -> str:
    """Generate a simple sine-wave ringtone WAV if it does not already exist.

    The tone alternates between two frequencies (440 Hz and 523 Hz) in a
    ring-ring … pause pattern, producing a classic phone-ring sound.

    Returns:
        Absolute path to the WAV file.
    """
    if os.path.isfile(_RINGTONE_PATH):
        return _RINGTONE_PATH

    sample_rate = 16_000
    amplitude = 20_000
    # Ring pattern: [(freq_hz, duration_s), ...]
    pattern = [
        (440, 0.25), (523, 0.25),
        (440, 0.25), (523, 0.25),
        (0,   0.50),  # pause
        (440, 0.25), (523, 0.25),
        (440, 0.25), (523, 0.25),
        (0,   0.80),  # longer pause
    ]

    frames: list[bytes] = []
    for freq, dur in pattern:
        n_samples = int(sample_rate * dur)
        for i in range(n_samples):
            if freq == 0:
                value = 0
            else:
                value = int(amplitude * math.sin(2.0 * math.pi * freq * i / sample_rate))
            frames.append(struct.pack("<h", value))

    try:
        os.makedirs(os.path.dirname(_RINGTONE_PATH), exist_ok=True)
        with wave.open(_RINGTONE_PATH, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(sample_rate)
            wf.writeframes(b"".join(frames))
        log.info("Ringtone generated at %s", _RINGTONE_PATH)
    except Exception:
        log.exception("Failed to generate ringtone")

    return _RINGTONE_PATH


# ──────────────────────────────────────────────────────────────────────────────
# Incoming-call overlay widget
# ──────────────────────────────────────────────────────────────────────────────

class _IncomingCallOverlay(QWidget):
    """Semi-transparent overlay with accept/reject buttons.

    Displayed on top of the main window when a call arrives.
    """

    accepted = Signal()
    rejected = Signal()

    _CALLER_DISPLAY_LEN = 30

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("incomingCallOverlay")
        self.setVisible(False)

        # Fill the entire parent
        self.setGeometry(parent.rect())

        self._build_ui()

        # Pulse animation on the card
        self._opacity_fx = QGraphicsOpacityEffect(self._card)
        self._card.setGraphicsEffect(self._opacity_fx)
        self._opacity_fx.setOpacity(1.0)

        self._pulse_anim = QPropertyAnimation(self._opacity_fx, b"opacity", self)
        self._pulse_anim.setDuration(900)
        self._pulse_anim.setStartValue(0.70)
        self._pulse_anim.setEndValue(1.0)
        self._pulse_anim.setEasingCurve(QEasingCurve.Type.InOutSine)
        self._pulse_anim.setLoopCount(-1)  # loop forever

        # Ringtone
        self._ringtone: QSoundEffect | None = None
        self._ring_timer: QTimer | None = None

    # ── UI ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Card
        self._card = QWidget()
        self._card.setObjectName("incomingCallCard")
        self._card.setFixedSize(340, 260)

        card_layout = QVBoxLayout(self._card)
        card_layout.setContentsMargins(28, 28, 28, 28)
        card_layout.setSpacing(14)
        card_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Icon / emoji
        icon_label = QLabel("📞")
        icon_label.setStyleSheet("font-size: 36px; background: transparent;")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(icon_label)

        # Title
        title = QLabel("Incoming Call")
        title.setObjectName("incomingTitleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title)

        # Caller
        self._caller_label = QLabel("")
        self._caller_label.setObjectName("incomingCallerLabel")
        self._caller_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._caller_label.setWordWrap(True)
        card_layout.addWidget(self._caller_label)

        card_layout.addSpacing(8)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(16)

        accept_btn = QPushButton("✅ Accept")
        accept_btn.setObjectName("acceptCallButton")
        accept_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        accept_btn.clicked.connect(self.accepted.emit)
        btn_row.addWidget(accept_btn)

        reject_btn = QPushButton("❌ Reject")
        reject_btn.setObjectName("rejectCallButton")
        reject_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        reject_btn.clicked.connect(self.rejected.emit)
        btn_row.addWidget(reject_btn)

        card_layout.addLayout(btn_row)
        root.addWidget(self._card)

    # ── Public API ────────────────────────────────────────────────────

    def show_for(self, caller: str) -> None:
        """Show the overlay for an incoming call from *caller*."""
        if len(caller) > self._CALLER_DISPLAY_LEN:
            display = caller[: self._CALLER_DISPLAY_LEN // 2] + "…" + caller[-(self._CALLER_DISPLAY_LEN // 2):]
        else:
            display = caller
        self._caller_label.setText(display)
        self._caller_label.setToolTip(caller)

        # Resize to parent
        if self.parent():
            self.setGeometry(self.parent().rect())

        self.setVisible(True)
        self.raise_()
        self._pulse_anim.start()
        self._play_ringtone()

    def dismiss(self) -> None:
        """Hide the overlay and stop audio."""
        self._pulse_anim.stop()
        self._opacity_fx.setOpacity(1.0)
        self._stop_ringtone()
        self.setVisible(False)

    # ── Ringtone playback ─────────────────────────────────────────────

    def _play_ringtone(self) -> None:
        """Start looping the ringtone."""
        path = _ensure_ringtone()
        if not os.path.isfile(path):
            return

        try:
            from PySide6.QtCore import QUrl
            self._ringtone = QSoundEffect(self)
            self._ringtone.setSource(QUrl.fromLocalFile(path))
            self._ringtone.setLoopCount(QSoundEffect.Infinite)
            self._ringtone.setVolume(0.6)
            self._ringtone.play()
        except Exception:
            log.exception("Failed to play ringtone")

    def _stop_ringtone(self) -> None:
        if self._ringtone is not None:
            try:
                self._ringtone.stop()
            except Exception:
                pass
            self._ringtone = None


# ──────────────────────────────────────────────────────────────────────────────
# Main window
# ──────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    """Primary application window for TorCall.

    Signals (for upstream call-manager wiring):
        call_requested(str):         User pressed Call with a target address.
        call_accepted():             User accepted an incoming call.
        call_rejected():             User rejected an incoming call.
        hangup_requested():          User pressed Hang Up.
        mute_toggled(bool):          Mute state changed.
        generate_address_requested(): User clicked New Address.
    """

    # ── Signals ───────────────────────────────────────────────────────
    call_requested = Signal(str)
    call_accepted = Signal()
    call_rejected = Signal()
    hangup_requested = Signal()
    mute_toggled = Signal(bool)
    generate_address_requested = Signal()
    contacts_requested = Signal()
    sas_confirmed = Signal()

    _WINDOW_WIDTH = 520
    _WINDOW_HEIGHT = 820

    def __init__(self) -> None:
        super().__init__()
        log.info("MainWindow: initialising")

        self.setWindowTitle(APP_NAME)
        # Resizable window: start at a comfortable size but let the user grow
        # it (or go full screen) so long .onion addresses, the SAS words and
        # the identity status all stay visible.
        self.setMinimumSize(QSize(460, 640))
        self.resize(QSize(self._WINDOW_WIDTH, self._WINDOW_HEIGHT))
        self.setStyleSheet(DARK_STYLESHEET)

        # F11 toggles full screen; Esc leaves it.
        self._fs_shortcut = QShortcut(QKeySequence(Qt.Key.Key_F11), self)
        self._fs_shortcut.activated.connect(self.toggle_fullscreen)
        self._esc_shortcut = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        self._esc_shortcut.activated.connect(self._exit_fullscreen)

        # Attempt to set an icon
        icon_path = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "icon.png")
        if os.path.isfile(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self._build_ui()
        self._connect_signals()

        log.info("MainWindow: ready")

    # ── UI assembly ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Build the main layout."""
        central = QWidget()
        central.setObjectName("centralWidget")
        self.setCentralWidget(central)

        root = QVBoxLayout(central)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(0)

        # 1 ── Title bar area ──────────────────────────────────────────
        title_row = QHBoxLayout()
        title_row.setSpacing(8)

        lock_label = QLabel("🔒")
        lock_label.setStyleSheet("font-size: 18px; background: transparent;")
        title_row.addWidget(lock_label)

        title_label = QLabel(APP_NAME)
        title_label.setObjectName("titleLabel")
        title_row.addWidget(title_label)

        title_row.addStretch()

        self._fullscreen_btn = QPushButton("⛶")
        self._fullscreen_btn.setObjectName("fullscreenButton")
        self._fullscreen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._fullscreen_btn.setToolTip("Toggle full screen (F11)")
        self._fullscreen_btn.setFixedWidth(36)
        self._fullscreen_btn.clicked.connect(self.toggle_fullscreen)
        title_row.addWidget(self._fullscreen_btn)

        version_label = QLabel(f"v{APP_VERSION}")
        version_label.setObjectName("versionLabel")
        title_row.addWidget(version_label)

        root.addLayout(title_row)
        root.addSpacing(20)

        # 2 ── Tor status section ─────────────────────────────────────
        self._tor_status_label = QLabel("Connecting to Tor…")
        self._tor_status_label.setObjectName("torStatusLabel")
        root.addWidget(self._tor_status_label)

        self._tor_progress = QProgressBar()
        self._tor_progress.setObjectName("torProgressBar")
        self._tor_progress.setRange(0, 100)
        self._tor_progress.setValue(0)
        self._tor_progress.setTextVisible(False)
        root.addWidget(self._tor_progress)
        root.addSpacing(18)

        # 3 ── Your address section ───────────────────────────────────
        addr_section_label = QLabel("Your Address:")
        addr_section_label.setObjectName("sectionLabel")
        root.addWidget(addr_section_label)
        root.addSpacing(4)

        self._address_label = QLabel("—")
        self._address_label.setObjectName("addressLabel")
        self._address_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._address_label.setWordWrap(True)
        root.addWidget(self._address_label)
        root.addSpacing(8)

        addr_btn_row = QHBoxLayout()
        addr_btn_row.setSpacing(10)

        self._copy_btn = QPushButton("📋 Copy")
        self._copy_btn.setObjectName("copyButton")
        self._copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._copy_btn.setToolTip("Copy your .onion address to clipboard")
        addr_btn_row.addWidget(self._copy_btn)

        self._generate_btn = QPushButton("🔄 New Address")
        self._generate_btn.setObjectName("generateButton")
        self._generate_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._generate_btn.setToolTip("Generate a new .onion address")
        addr_btn_row.addWidget(self._generate_btn)

        self._contacts_btn = QPushButton("📇 Contacts")
        self._contacts_btn.setObjectName("generateButton")
        self._contacts_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._contacts_btn.setToolTip("Open your address book")
        addr_btn_row.addWidget(self._contacts_btn)

        addr_btn_row.addStretch()
        root.addLayout(addr_btn_row)
        root.addSpacing(14)

        # 4 ── Separator ──────────────────────────────────────────────
        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.Shape.HLine)
        root.addWidget(sep)
        root.addSpacing(14)

        # 5 ── Call section ───────────────────────────────────────────
        call_section_label = QLabel("Call Address:")
        call_section_label.setObjectName("sectionLabel")
        root.addWidget(call_section_label)
        root.addSpacing(4)

        self._call_input = QLineEdit()
        self._call_input.setPlaceholderText("Enter .onion address…")
        root.addWidget(self._call_input)
        root.addSpacing(10)

        self._call_btn = QPushButton("📞  Call")
        self._call_btn.setObjectName("callButton")
        self._call_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        root.addWidget(self._call_btn)
        root.addSpacing(14)

        # 6 ── Status section ─────────────────────────────────────────
        self._status_label = QLabel("Idle")
        self._status_label.setObjectName("statusLabel")
        self._status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self._status_label)
        root.addSpacing(10)

        # 7 ── Call widget (hidden by default) ────────────────────────
        self._call_widget = CallWidget()
        self._call_widget.setVisible(False)
        root.addWidget(self._call_widget)

        root.addStretch()

        # ── Incoming call overlay (floats above everything) ──────────
        self._incoming_overlay = _IncomingCallOverlay(central)
        self._incoming_overlay.setVisible(False)

    # ── Signal wiring ─────────────────────────────────────────────────

    def _connect_signals(self) -> None:
        # Buttons → own signals
        self._call_btn.clicked.connect(self._on_call_clicked)
        self._copy_btn.clicked.connect(self.copy_address_to_clipboard)
        self._generate_btn.clicked.connect(self.generate_address_requested.emit)
        self._contacts_btn.clicked.connect(self.contacts_requested.emit)

        # Call widget → own signals
        self._call_widget.hangup_clicked.connect(self.hangup_requested.emit)
        self._call_widget.mute_toggled.connect(self.mute_toggled.emit)
        self._call_widget.sas_confirmed.connect(self.sas_confirmed.emit)

        # Incoming call overlay
        self._incoming_overlay.accepted.connect(self._on_incoming_accepted)
        self._incoming_overlay.rejected.connect(self._on_incoming_rejected)

        # Enter key in call input
        self._call_input.returnPressed.connect(self._on_call_clicked)

    # ── Public API ────────────────────────────────────────────────────

    def set_tor_status(self, status: str, progress: int) -> None:
        """Update the Tor connection status display.

        Args:
            status:   Human-readable status text (e.g. ``"Connected ✓"``).
            progress: Bootstrap progress 0–100.  When 100, the progress bar
                      is hidden automatically.
        """
        self._tor_status_label.setText(status)

        # Colour-code the label
        if "error" in status.lower() or "✗" in status:
            self._tor_status_label.setStyleSheet(f"color: {Colors.DANGER};")
        elif "connected" in status.lower() or "✓" in status:
            self._tor_status_label.setStyleSheet(f"color: {Colors.SUCCESS};")
        else:
            self._tor_status_label.setStyleSheet(f"color: {Colors.WARNING};")

        progress = max(0, min(100, progress))
        self._tor_progress.setValue(progress)
        self._tor_progress.setVisible(progress < 100)

    def set_address(self, address: str) -> None:
        """Display the local ``.onion`` address.

        Args:
            address: Full .onion address string.
        """
        self._address_label.setText(address)
        log.info("MainWindow: address set to %s", address[:16] + "…")

    def set_call_status(self, status: str) -> None:
        """Update the call-status label text.

        Args:
            status: e.g. ``"Idle"``, ``"Dialing…"``, ``"Ringing…"``,
                    ``"Connected"``.
        """
        self._status_label.setText(status)

    def prefill_call_address(self, address: str) -> None:
        """Put *address* into the call input box (e.g. picked from the
        address book) so the user can review before dialing."""
        self._call_input.setText(address)

    def show_incoming_call(self, caller: str) -> None:
        """Display the incoming-call overlay.

        Args:
            caller: The remote ``.onion`` address of the caller.
        """
        log.info("MainWindow: showing incoming call from %s", caller[:16])
        self._incoming_overlay.show_for(caller)

    def hide_incoming_call(self) -> None:
        """Dismiss the incoming-call overlay."""
        self._incoming_overlay.dismiss()

    def show_call_widget(self, peer: str) -> None:
        """Switch to the in-call view.

        Args:
            peer: The remote ``.onion`` address.
        """
        self._call_widget.start_call(peer)
        self._call_input.setEnabled(False)
        self._call_btn.setEnabled(False)

    def hide_call_widget(self) -> None:
        """Switch back to the idle view."""
        self._call_widget.end_call()
        self._call_input.setEnabled(True)
        self._call_btn.setEnabled(True)

    def update_audio_level(self, level: float) -> None:
        """Forward the audio level to the call widget.

        Args:
            level: ``0.0`` – ``1.0``.
        """
        self._call_widget.update_audio_level(level)

    def show_sas(self, sas: str) -> None:
        """Forward the Short Authentication String to the call widget.

        Args:
            sas: The word code both peers compare aloud to detect a MITM.
        """
        self._call_widget.set_sas(sas)

    def show_peer_identity(self, info: dict) -> None:
        """Forward the peer identity verification result to the call widget.

        Args:
            info: Dict with ``status``, ``fingerprint`` and ``address``.
        """
        self._call_widget.set_peer_identity(info)

    def show_sas_confirmation_required(self, required: bool) -> None:
        """Forward the SAS-gate state to the call widget.

        Args:
            required: True while audio is held pending the user confirming
                the SAS words match.
        """
        self._call_widget.set_sas_confirmation_required(required)

    def copy_address_to_clipboard(self) -> None:
        """Copy the current .onion address to the system clipboard."""
        address = self._address_label.text()
        if address and address != "—":
            clipboard: QClipboard = QGuiApplication.clipboard()
            clipboard.setText(address)
            log.info("MainWindow: address copied to clipboard")
            # Brief visual feedback
            self._copy_btn.setText("✅ Copied!")
            QTimer.singleShot(1500, lambda: self._copy_btn.setText("📋 Copy"))

    # ── Private slots ─────────────────────────────────────────────────

    def _on_call_clicked(self) -> None:
        target = self._call_input.text().strip()
        if target:
            log.info("MainWindow: call requested → %s", target[:16])
            self.call_requested.emit(target)

    def _on_incoming_accepted(self) -> None:
        log.info("MainWindow: incoming call accepted")
        self.hide_incoming_call()
        self.call_accepted.emit()

    def _on_incoming_rejected(self) -> None:
        log.info("MainWindow: incoming call rejected")
        self.hide_incoming_call()
        self.call_rejected.emit()

    # ── Resize handling (keep overlay in sync) ────────────────────────

    def resizeEvent(self, event) -> None:  # noqa: N802
        """Keep the incoming-call overlay sized to the central widget."""
        super().resizeEvent(event)
        cw = self.centralWidget()
        if cw and self._incoming_overlay:
            self._incoming_overlay.setGeometry(cw.rect())

    # ── Full screen ───────────────────────────────────────────────────

    def toggle_fullscreen(self) -> None:
        """Switch between full screen and normal window mode."""
        if self.isFullScreen():
            self.showNormal()
            self._fullscreen_btn.setText("⛶")
        else:
            self.showFullScreen()
            self._fullscreen_btn.setText("🗗")

    def _exit_fullscreen(self) -> None:
        """Leave full screen if currently active (bound to Esc)."""
        if self.isFullScreen():
            self.showNormal()
            self._fullscreen_btn.setText("⛶")
