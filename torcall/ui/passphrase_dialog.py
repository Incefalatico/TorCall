"""
TorCall startup passphrase dialog.

Asks the user for the at-rest encryption passphrase used to protect the
hidden-service key, the long-term identity, and the pinned-contacts
database.  The passphrase is never written to disk — it lives only in
process memory for the duration of the session (see
:func:`torcall.utils.config.set_passphrase`).

If a saved identity is already encrypted, the dialog validates the
entered passphrase against it so the user gets immediate feedback instead
of a silent failure later.
"""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QCheckBox,
    QWidget,
)

from torcall.core.crypto import decrypt_at_rest, is_vault_blob
from torcall.ui.styles import Colors, DARK_STYLESHEET
from torcall.utils.config import IDENTITY_KEY_FILE
from torcall.utils.logger import log


def _existing_vault_path() -> Optional[str]:
    """Return the path of an encrypted identity file, if one exists."""
    try:
        if os.path.isfile(IDENTITY_KEY_FILE):
            with open(IDENTITY_KEY_FILE, "rb") as fh:
                if is_vault_blob(fh.read()):
                    return IDENTITY_KEY_FILE
    except OSError:
        log.exception("Could not inspect identity file for encryption status")
    return None


class PassphraseDialog(QDialog):
    """Modal dialog that collects the at-rest passphrase at startup."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)

        self._vault_path = _existing_vault_path()
        self._passphrase = ""

        self.setWindowTitle("TorCall — Unlock")
        self.setModal(True)
        self.setMinimumWidth(420)
        self.setStyleSheet(DARK_STYLESHEET)

        self._build_ui()

    # ── UI ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 24)
        layout.setSpacing(14)

        unlocking = self._vault_path is not None

        title = QLabel("Unlock your identity" if unlocking else "Protect your identity")
        title.setStyleSheet(
            f"color: {Colors.TEXT_PRIMARY}; font-size: 18px; font-weight: 600;"
        )
        layout.addWidget(title)

        if unlocking:
            blurb = (
                "Enter your passphrase to decrypt your saved .onion identity "
                "and contacts."
            )
        else:
            blurb = (
                "Set a passphrase to encrypt your .onion key, long-term "
                "identity, and contacts at rest. Leave it empty to store them "
                "in plaintext (not recommended)."
            )
        subtitle = QLabel(blurb)
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color: {Colors.TEXT_SECONDARY}; font-size: 13px;")
        layout.addWidget(subtitle)

        self._pass_input = QLineEdit()
        self._pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_input.setPlaceholderText("Passphrase")
        self._pass_input.returnPressed.connect(self._on_accept)
        layout.addWidget(self._pass_input)

        # Confirm field only when creating a new passphrase.
        self._confirm_input: Optional[QLineEdit] = None
        if not unlocking:
            self._confirm_input = QLineEdit()
            self._confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            self._confirm_input.setPlaceholderText("Confirm passphrase")
            self._confirm_input.returnPressed.connect(self._on_accept)
            layout.addWidget(self._confirm_input)

        show = QCheckBox("Show passphrase")
        show.toggled.connect(self._on_toggle_echo)
        layout.addWidget(show)

        self._error = QLabel("")
        self._error.setWordWrap(True)
        self._error.setStyleSheet(f"color: {Colors.DANGER}; font-size: 12px;")
        self._error.hide()
        layout.addWidget(self._error)

        # Buttons
        buttons = QHBoxLayout()
        buttons.addStretch(1)

        if not unlocking:
            skip_btn = QPushButton("Skip")
            skip_btn.clicked.connect(self._on_skip)
            buttons.addWidget(skip_btn)

        self._ok_btn = QPushButton("Unlock" if unlocking else "Continue")
        self._ok_btn.setDefault(True)
        self._ok_btn.clicked.connect(self._on_accept)
        buttons.addWidget(self._ok_btn)

        layout.addLayout(buttons)

        self._pass_input.setFocus()

    # ── Behaviour ──────────────────────────────────────────────────────

    def _on_toggle_echo(self, checked: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        self._pass_input.setEchoMode(mode)
        if self._confirm_input is not None:
            self._confirm_input.setEchoMode(mode)

    def _show_error(self, message: str) -> None:
        self._error.setText(message)
        self._error.show()

    def _on_skip(self) -> None:
        """User opted out of encryption for this session."""
        self._passphrase = ""
        self.accept()

    def _on_accept(self) -> None:
        passphrase = self._pass_input.text()

        if self._vault_path is not None:
            # Unlocking an existing encrypted identity — validate it.
            if not passphrase:
                self._show_error("Enter your passphrase to continue.")
                return
            if not self._verify(passphrase):
                self._show_error("Incorrect passphrase. Please try again.")
                self._pass_input.selectAll()
                self._pass_input.setFocus()
                return
        else:
            # Creating a new passphrase — require confirmation match.
            confirm = self._confirm_input.text() if self._confirm_input else ""
            if passphrase != confirm:
                self._show_error("Passphrases do not match.")
                return

        self._passphrase = passphrase
        self.accept()

    def _verify(self, passphrase: str) -> bool:
        """Return True if *passphrase* decrypts the saved identity."""
        try:
            with open(self._vault_path, "rb") as fh:
                blob = fh.read()
            decrypt_at_rest(passphrase, blob)
            return True
        except Exception:
            return False

    # ── Result ─────────────────────────────────────────────────────────

    def passphrase(self) -> str:
        """Return the passphrase the user supplied (may be empty)."""
        return self._passphrase
