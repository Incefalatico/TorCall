"""
TorCall dark theme stylesheet and colour palette.

The visual language uses a near-black background with purple accents
(echoing the Tor Project brand) to create a premium, modern look.
"""

from __future__ import annotations


# ── Colour palette ────────────────────────────────────────────────────

class Colors:
    """Centralised colour tokens used across the UI."""

    # Backgrounds
    BG_PRIMARY    = "#0a0a12"
    BG_SECONDARY  = "#12121f"
    BG_TERTIARY   = "#1a1a2e"
    BG_INPUT      = "#16162a"

    # Accent — purple (Tor brand)
    ACCENT         = "#7c3aed"
    ACCENT_HOVER   = "#8b5cf6"
    ACCENT_PRESSED = "#6d28d9"

    # Semantic
    SUCCESS        = "#22c55e"
    SUCCESS_HOVER  = "#16a34a"
    WARNING        = "#f59e0b"
    DANGER         = "#ef4444"
    DANGER_HOVER   = "#dc2626"
    DANGER_PRESSED = "#b91c1c"

    # Text
    TEXT_PRIMARY   = "#e2e8f0"
    TEXT_SECONDARY = "#94a3b8"
    TEXT_DISABLED  = "#475569"

    # Borders
    BORDER       = "#1e293b"
    BORDER_FOCUS = "#7c3aed"

    # Misc
    TRANSPARENT = "transparent"


# ── QSS stylesheet ───────────────────────────────────────────────────

DARK_STYLESHEET = f"""
/* ═══════════════════════════════════════════════════════════════════
   TorCall Dark Theme
   ═══════════════════════════════════════════════════════════════════ */

/* ── Base ────────────────────────────────────────────────────────── */
QMainWindow, QWidget {{
    background-color: {Colors.BG_PRIMARY};
    color: {Colors.TEXT_PRIMARY};
    font-family: "Segoe UI", "Inter", "Helvetica Neue", sans-serif;
    font-size: 13px;
}}

QWidget#centralWidget {{
    background-color: {Colors.BG_PRIMARY};
}}

/* ── Labels ──────────────────────────────────────────────────────── */
QLabel {{
    color: {Colors.TEXT_PRIMARY};
    background: transparent;
    padding: 0px;
}}

QLabel#titleLabel {{
    font-size: 22px;
    font-weight: 700;
    color: {Colors.TEXT_PRIMARY};
    letter-spacing: 1px;
}}

QLabel#subtitleLabel {{
    font-size: 11px;
    color: {Colors.TEXT_SECONDARY};
}}

QLabel#sectionLabel {{
    font-size: 12px;
    font-weight: 600;
    color: {Colors.TEXT_SECONDARY};
    text-transform: uppercase;
    letter-spacing: 0.5px;
    padding-top: 4px;
}}

QLabel#addressLabel {{
    font-family: "Cascadia Code", "Consolas", "Fira Code", monospace;
    font-size: 13px;
    color: {Colors.ACCENT_HOVER};
    background-color: {Colors.BG_INPUT};
    border: 1px solid {Colors.BORDER};
    border-radius: 6px;
    padding: 10px 12px;
    selection-background-color: {Colors.ACCENT};
}}

QLabel#statusLabel {{
    font-size: 13px;
    color: {Colors.TEXT_SECONDARY};
    padding: 8px 0px;
}}

QLabel#timerLabel {{
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 36px;
    font-weight: 700;
    color: {Colors.TEXT_PRIMARY};
    padding: 8px;
}}

QLabel#peerLabel {{
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    color: {Colors.TEXT_SECONDARY};
}}

QLabel#sasCaption {{
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: {Colors.TEXT_SECONDARY};
}}

QLabel#sasLabel {{
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 16px;
    font-weight: 700;
    color: {Colors.ACCENT};
    padding: 4px 12px;
    background-color: {Colors.BG_TERTIARY};
    border: 1px solid {Colors.ACCENT};
    border-radius: 8px;
}}

QLabel#identityLabel {{
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    font-weight: 600;
    color: {Colors.TEXT_SECONDARY};
    padding: 3px 10px;
}}

QLabel#torStatusLabel {{
    font-size: 13px;
    font-weight: 600;
    padding: 4px 0px;
}}

QLabel#incomingTitleLabel {{
    font-size: 20px;
    font-weight: 700;
    color: {Colors.TEXT_PRIMARY};
}}

QLabel#incomingCallerLabel {{
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    color: {Colors.TEXT_SECONDARY};
    padding: 4px 0px;
}}

/* ── Buttons ─────────────────────────────────────────────────────── */
QPushButton {{
    background-color: {Colors.BG_TERTIARY};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 13px;
    font-weight: 600;
    min-height: 18px;
}}
QPushButton:hover {{
    background-color: {Colors.ACCENT};
    border-color: {Colors.ACCENT};
    color: #ffffff;
}}
QPushButton:pressed {{
    background-color: {Colors.ACCENT_PRESSED};
    border-color: {Colors.ACCENT_PRESSED};
}}
QPushButton:disabled {{
    background-color: {Colors.BG_SECONDARY};
    color: {Colors.TEXT_DISABLED};
    border-color: {Colors.BG_SECONDARY};
}}

/* Call button — prominent green */
QPushButton#callButton {{
    background-color: {Colors.SUCCESS};
    color: #ffffff;
    border: none;
    font-size: 15px;
    font-weight: 700;
    padding: 14px 20px;
    border-radius: 10px;
    min-height: 24px;
}}
QPushButton#callButton:hover {{
    background-color: {Colors.SUCCESS_HOVER};
}}
QPushButton#callButton:pressed {{
    background-color: #15803d;
}}
QPushButton#callButton:disabled {{
    background-color: {Colors.BG_TERTIARY};
    color: {Colors.TEXT_DISABLED};
}}

/* Hang up button — red */
QPushButton#hangupButton {{
    background-color: {Colors.DANGER};
    color: #ffffff;
    border: none;
    font-size: 15px;
    font-weight: 700;
    padding: 14px 24px;
    border-radius: 10px;
    min-height: 24px;
}}
QPushButton#hangupButton:hover {{
    background-color: {Colors.DANGER_HOVER};
}}
QPushButton#hangupButton:pressed {{
    background-color: {Colors.DANGER_PRESSED};
}}

/* Mute toggle */
QPushButton#muteButton {{
    background-color: {Colors.BG_TERTIARY};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 10px;
    padding: 14px 24px;
    font-size: 15px;
    font-weight: 700;
    min-height: 24px;
}}
QPushButton#muteButton:hover {{
    background-color: {Colors.BG_INPUT};
    border-color: {Colors.ACCENT};
}}
QPushButton#muteButton:checked {{
    background-color: {Colors.DANGER};
    border-color: {Colors.DANGER};
    color: #ffffff;
}}

/* SAS confirm button — releases gated audio once the user verifies words */
QPushButton#sasConfirmButton {{
    background-color: {Colors.SUCCESS};
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 10px 20px;
    font-size: 14px;
    font-weight: 700;
}}
QPushButton#sasConfirmButton:hover {{
    background-color: {Colors.SUCCESS_HOVER};
}}
QPushButton#sasConfirmButton:disabled {{
    background-color: {Colors.BG_TERTIARY};
    color: {Colors.TEXT_SECONDARY};
}}

/* Generate / New Address button */
QPushButton#generateButton {{
    background-color: {Colors.ACCENT};
    color: #ffffff;
    border: none;
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 12px;
}}
QPushButton#generateButton:hover {{
    background-color: {Colors.ACCENT_HOVER};
}}
QPushButton#generateButton:pressed {{
    background-color: {Colors.ACCENT_PRESSED};
}}

/* Copy button — ghost / transparent */
QPushButton#copyButton {{
    background-color: transparent;
    color: {Colors.TEXT_SECONDARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    padding: 8px 16px;
    font-size: 12px;
}}
QPushButton#copyButton:hover {{
    background-color: {Colors.BG_TERTIARY};
    color: {Colors.TEXT_PRIMARY};
    border-color: {Colors.ACCENT};
}}

/* Accept incoming call */
QPushButton#acceptButton {{
    background-color: {Colors.SUCCESS};
    color: #ffffff;
    border: none;
    border-radius: 10px;
    padding: 12px 32px;
    font-size: 14px;
    font-weight: 700;
}}
QPushButton#acceptButton:hover {{
    background-color: {Colors.SUCCESS_HOVER};
}}

/* Reject incoming call */
QPushButton#rejectButton {{
    background-color: {Colors.DANGER};
    color: #ffffff;
    border: none;
    border-radius: 10px;
    padding: 12px 32px;
    font-size: 14px;
    font-weight: 700;
}}
QPushButton#rejectButton:hover {{
    background-color: {Colors.DANGER_HOVER};
}}

/* ── Line edits ──────────────────────────────────────────────────── */
QLineEdit {{
    background-color: {Colors.BG_INPUT};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    padding: 12px 14px;
    font-size: 13px;
    font-family: "Cascadia Code", "Consolas", monospace;
    selection-background-color: {Colors.ACCENT};
}}
QLineEdit:focus {{
    border-color: {Colors.BORDER_FOCUS};
}}
QLineEdit:disabled {{
    background-color: {Colors.BG_SECONDARY};
    color: {Colors.TEXT_DISABLED};
}}

/* ── Progress bar ────────────────────────────────────────────────── */
QProgressBar {{
    background-color: {Colors.BG_TERTIARY};
    border: none;
    border-radius: 4px;
    height: 6px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background-color: {Colors.ACCENT};
    border-radius: 4px;
}}

/* Audio level bar */
QProgressBar#audioLevelBar {{
    background-color: {Colors.BG_TERTIARY};
    border: none;
    border-radius: 3px;
    height: 4px;
}}
QProgressBar#audioLevelBar::chunk {{
    background-color: {Colors.SUCCESS};
    border-radius: 3px;
}}

/* ── Separators ──────────────────────────────────────────────────── */
QFrame#separator {{
    background-color: {Colors.BORDER};
    border: none;
    max-height: 1px;
    min-height: 1px;
}}

/* ── Scroll bars ─────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background: {Colors.BG_PRIMARY};
    width: 8px;
    margin: 0;
    border: none;
}}
QScrollBar::handle:vertical {{
    background: {Colors.BG_TERTIARY};
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: {Colors.ACCENT};
}}
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* ── Incoming call overlay ───────────────────────────────────────── */
QWidget#incomingCallOverlay {{
    background-color: rgba(10, 10, 18, 230);
    border-radius: 12px;
}}

/* ── Tooltips ────────────────────────────────────────────────────── */
QToolTip {{
    background-color: {Colors.BG_TERTIARY};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 4px;
    padding: 6px 10px;
    font-size: 12px;
}}

/* ── Full-screen toggle button ───────────────────────────────────── */
QPushButton#fullscreenButton {{
    background-color: transparent;
    color: {Colors.TEXT_SECONDARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 6px;
    padding: 2px 6px;
    font-size: 14px;
}}
QPushButton#fullscreenButton:hover {{
    color: {Colors.TEXT_PRIMARY};
    border-color: {Colors.ACCENT};
}}

/* ── Contacts list (address book) ────────────────────────────────── */
QListWidget#contactsList {{
    background-color: {Colors.BG_INPUT};
    color: {Colors.TEXT_PRIMARY};
    border: 1px solid {Colors.BORDER};
    border-radius: 8px;
    padding: 6px;
    font-size: 13px;
}}
QListWidget#contactsList::item {{
    padding: 10px 12px;
    border-radius: 6px;
    margin: 2px 0;
}}
QListWidget#contactsList::item:selected {{
    background-color: {Colors.ACCENT};
    color: #ffffff;
}}
QListWidget#contactsList::item:hover {{
    background-color: {Colors.BG_TERTIARY};
}}
"""
