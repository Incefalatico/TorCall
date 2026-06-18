"""
TorCall — in-call widget.

Displays the active-call interface: call duration timer, audio level
visualisation, peer address, and mute/hang-up controls.

Usage::

    call = CallWidget()
    call.start_call("abc123…onion")
    call.mute_toggled.connect(handle_mute)
    call.hangup_clicked.connect(handle_hangup)
"""

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from torcall.utils.logger import log


class CallWidget(QWidget):
    """Widget shown during an active voice call.

    Signals:
        mute_toggled(bool): Emitted when the user toggles mute.
        hangup_clicked():   Emitted when the user presses hang-up.
    """

    # ── Signals ───────────────────────────────────────────────────────
    mute_toggled = Signal(bool)
    hangup_clicked = Signal()
    sas_confirmed = Signal()

    # Maximum address characters shown before truncation
    _ADDR_DISPLAY_LEN = 24

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("callWidget")

        self._elapsed_seconds: int = 0
        self._is_muted: bool = False

        self._build_ui()
        self._connect_signals()

        # 1-second tick timer for the call clock
        self._tick_timer = QTimer(self)
        self._tick_timer.setInterval(1_000)
        self._tick_timer.timeout.connect(self._on_tick)

    # ── UI construction ───────────────────────────────────────────────

    def _build_ui(self) -> None:
        """Assemble all child widgets and layouts."""
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 28, 24, 24)
        root.setSpacing(12)
        root.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Call status indicator
        self._call_status_label = QLabel("In Call")
        self._call_status_label.setObjectName("sectionLabel")
        self._call_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self._call_status_label)

        # Timer
        self._timer_label = QLabel("00:00")
        self._timer_label.setObjectName("timerLabel")
        self._timer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self._timer_label)

        # Peer address
        self._peer_label = QLabel("")
        self._peer_label.setObjectName("peerLabel")
        self._peer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(self._peer_label)

        # Short Authentication String — read aloud to verify no MITM
        self._sas_caption = QLabel("Verify aloud:")
        self._sas_caption.setObjectName("sasCaption")
        self._sas_caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._sas_caption.setVisible(False)
        root.addWidget(self._sas_caption)

        self._sas_label = QLabel("")
        self._sas_label.setObjectName("sasLabel")
        self._sas_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._sas_label.setWordWrap(True)
        self._sas_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._sas_label.setVisible(False)
        self._sas_label.setToolTip(
            "Read these words aloud to your peer. If they don't match on "
            "both sides, the call may be intercepted — hang up."
        )
        root.addWidget(self._sas_label)

        # SAS confirm button — only shown when audio is gated on SAS
        # verification (TORCALL_REQUIRE_SAS).  Until pressed, audio is held.
        self._sas_confirm_btn = QPushButton("✓ Words match — start audio")
        self._sas_confirm_btn.setObjectName("sasConfirmButton")
        self._sas_confirm_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._sas_confirm_btn.setVisible(False)
        root.addWidget(self._sas_confirm_btn, alignment=Qt.AlignmentFlag.AlignCenter)

        # Peer identity (TOFU) status
        self._identity_label = QLabel("")
        self._identity_label.setObjectName("identityLabel")
        self._identity_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._identity_label.setWordWrap(True)
        self._identity_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._identity_label.setVisible(False)
        root.addWidget(self._identity_label)

        root.addSpacing(8)

        # Audio level bar
        self._audio_bar = QProgressBar()
        self._audio_bar.setObjectName("audioLevelBar")
        self._audio_bar.setRange(0, 100)
        self._audio_bar.setValue(0)
        self._audio_bar.setTextVisible(False)
        self._audio_bar.setFixedHeight(6)
        root.addWidget(self._audio_bar)

        root.addSpacing(16)

        # Buttons row: Mute | Hang Up
        btn_row = QHBoxLayout()
        btn_row.setSpacing(16)

        self._mute_btn = QPushButton("🎙️ Mute")
        self._mute_btn.setObjectName("muteButton")
        self._mute_btn.setCheckable(True)
        self._mute_btn.setMinimumWidth(120)
        self._mute_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_row.addWidget(self._mute_btn)

        self._hangup_btn = QPushButton("📞 Hang Up")
        self._hangup_btn.setObjectName("hangupButton")
        self._hangup_btn.setMinimumWidth(120)
        self._hangup_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_row.addWidget(self._hangup_btn)

        root.addLayout(btn_row)

    # ── Internal signal wiring ────────────────────────────────────────

    def _connect_signals(self) -> None:
        self._mute_btn.toggled.connect(self._on_mute_toggled)
        self._hangup_btn.clicked.connect(self._on_hangup_clicked)
        self._sas_confirm_btn.clicked.connect(self._on_sas_confirm_clicked)

    # ── Public API ────────────────────────────────────────────────────

    def start_call(self, peer_address: str) -> None:
        """Begin displaying the in-call UI for *peer_address*.

        Resets the timer to 00:00 and starts counting.

        Args:
            peer_address: The remote .onion address.
        """
        log.info("CallWidget: call started with %s", peer_address)
        self._elapsed_seconds = 0
        self._timer_label.setText("00:00")
        self._set_peer_text(peer_address)
        self._audio_bar.setValue(0)
        self.set_muted(False)
        self.clear_sas()
        self._tick_timer.start()
        self.setVisible(True)

    def end_call(self) -> None:
        """Stop the timer and reset the widget to its idle state."""
        log.info("CallWidget: call ended (duration %ss)", self._elapsed_seconds)
        self._tick_timer.stop()
        self._elapsed_seconds = 0
        self._timer_label.setText("00:00")
        self._peer_label.setText("")
        self._audio_bar.setValue(0)
        self.set_muted(False)
        self.clear_sas()
        self.setVisible(False)

    def set_muted(self, muted: bool) -> None:
        """Update the mute button visual without emitting a signal.

        Args:
            muted: ``True`` to display as muted.
        """
        self._is_muted = muted
        self._mute_btn.blockSignals(True)
        self._mute_btn.setChecked(muted)
        self._mute_btn.setText("🔇 Unmute" if muted else "🎙️ Mute")
        self._mute_btn.blockSignals(False)

    def update_audio_level(self, level: float) -> None:
        """Set the audio-level indicator.

        Args:
            level: A value between ``0.0`` (silence) and ``1.0`` (max).
        """
        clamped = max(0.0, min(1.0, level))
        self._audio_bar.setValue(int(clamped * 100))

    def set_sas(self, sas: str) -> None:
        """Display the Short Authentication String for verbal verification.

        Args:
            sas: The space-separated word code both peers must compare.
        """
        log.info("CallWidget: SAS ready")
        self._sas_label.setText(sas)
        self._sas_caption.setVisible(True)
        self._sas_label.setVisible(True)

    def clear_sas(self) -> None:
        """Hide and reset the SAS display."""
        self._sas_label.setText("")
        self._sas_caption.setVisible(False)
        self._sas_label.setVisible(False)
        self._identity_label.setText("")
        self._identity_label.setVisible(False)
        self._sas_confirm_btn.setVisible(False)
        self._sas_confirm_btn.setEnabled(True)
        self._sas_confirm_btn.setText("✓ Words match — start audio")

    def set_sas_confirmation_required(self, required: bool) -> None:
        """Show or hide the SAS confirm button.

        When *required* is True, audio is being withheld until the user
        confirms the spoken SAS words match; pressing the button releases
        it.  When False, the gate is satisfied (or disabled) so the button
        is hidden.
        """
        if required:
            self._sas_confirm_btn.setVisible(True)
            self._sas_confirm_btn.setEnabled(True)
            self._sas_confirm_btn.setText("✓ Words match — start audio")
        else:
            self._sas_confirm_btn.setVisible(False)

    def set_peer_identity(self, info: dict) -> None:
        """Display the peer's identity verification status (TOFU).

        Args:
            info: Dict with ``status``, ``fingerprint``, ``address`` and an
                optional human-readable ``name``.
        """
        status = info.get("status", "")
        fp = info.get("fingerprint", "")
        name = info.get("name", "")
        who = name if name else fp
        if status == "match":
            text = f"✓ Known contact ({who})"
        elif status == "new":
            text = f"🔑 New contact pinned ({fp})"
        elif status == "known_new_address":
            text = f"↪ {who} — known contact, new address"
        elif status == "mismatch":
            text = f"⚠ IDENTITY CHANGED ({fp}) — verify before trusting"
        elif status == "unsigned":
            text = "⚠ Peer sent no identity — cannot recognise them"
        else:
            text = ""
        log.info("CallWidget: peer identity status=%s", status)
        self._identity_label.setText(text)
        self._identity_label.setVisible(bool(text))

    # ── Private helpers ───────────────────────────────────────────────

    def _set_peer_text(self, address: str) -> None:
        """Show a truncated version of the peer address."""
        if len(address) > self._ADDR_DISPLAY_LEN:
            display = address[: self._ADDR_DISPLAY_LEN // 2] + "…" + address[-(self._ADDR_DISPLAY_LEN // 2):]
        else:
            display = address
        self._peer_label.setText(display)
        self._peer_label.setToolTip(address)

    def _format_time(self, seconds: int) -> str:
        """Return *seconds* formatted as ``MM:SS`` (or ``H:MM:SS`` for long calls)."""
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}:{m:02d}:{s:02d}"
        return f"{m:02d}:{s:02d}"

    # ── Slots ─────────────────────────────────────────────────────────

    def _on_tick(self) -> None:
        self._elapsed_seconds += 1
        self._timer_label.setText(self._format_time(self._elapsed_seconds))

    def _on_mute_toggled(self, checked: bool) -> None:
        self._is_muted = checked
        self._mute_btn.setText("🔇 Unmute" if checked else "🎙️ Mute")
        log.info("CallWidget: mute toggled → %s", "muted" if checked else "unmuted")
        self.mute_toggled.emit(checked)

    def _on_hangup_clicked(self) -> None:
        log.info("CallWidget: hang-up clicked")
        self.hangup_clicked.emit()

    def _on_sas_confirm_clicked(self) -> None:
        log.info("CallWidget: SAS confirmed by user")
        self._sas_confirm_btn.setEnabled(False)
        self._sas_confirm_btn.setText("✓ Audio enabled")
        self.sas_confirmed.emit()
