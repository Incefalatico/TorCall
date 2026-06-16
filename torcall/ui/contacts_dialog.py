"""
TorCall — address book (contacts) dialog.

Shows every contact TorCall has pinned via trust-on-first-use, keyed by
their long-term Ed25519 identity.  Because ``.onion`` addresses are
ephemeral, a single contact may be reachable from several addresses; each
list entry therefore groups all known addresses for one identity.

From here the user can:

* give a contact a human-readable name,
* copy one of their ``.onion`` addresses, and
* pick an address to dial (it is pre-filled into the main window).

The dialog never writes to disk directly — it asks the call manager to
persist renames so the at-rest encryption stays consistent.
"""

from __future__ import annotations

from typing import Callable, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from torcall.ui.styles import Colors, DARK_STYLESHEET
from torcall.utils.logger import log


class ContactsDialog(QDialog):
    """Modal address book listing every known contact.

    Signals:
        call_requested(str): Emitted with a ``.onion`` address the user
            chose to dial.  The caller (main window) is responsible for
            actually placing the call.
    """

    call_requested = Signal(str)

    def __init__(
        self,
        list_contacts: Callable[[], list[dict]],
        rename_contact: Callable[[str, str], None],
        remove_contact: Callable[[str], int],
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)

        self._list_contacts = list_contacts
        self._rename_contact = rename_contact
        self._remove_contact = remove_contact

        self.setWindowTitle("TorCall — Contacts")
        self.setModal(True)
        self.setStyleSheet(DARK_STYLESHEET)
        self.setMinimumSize(440, 420)

        self._build_ui()
        self._reload()

    # ── UI ────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        title = QLabel("📇  Contacts")
        title.setObjectName("titleLabel")
        root.addWidget(title)

        subtitle = QLabel(
            "Contacts are recognised by their identity key, so they stay "
            "the same even if their .onion address changes."
        )
        subtitle.setObjectName("sectionLabel")
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        self._list = QListWidget()
        self._list.setObjectName("contactsList")
        self._list.itemSelectionChanged.connect(self._on_selection_changed)
        self._list.itemDoubleClicked.connect(lambda _i: self._on_call())
        root.addWidget(self._list, stretch=1)

        self._empty_label = QLabel("No contacts yet. They appear here after your first call.")
        self._empty_label.setObjectName("sectionLabel")
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setWordWrap(True)
        root.addWidget(self._empty_label)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self._call_btn = QPushButton("📞  Call")
        self._call_btn.setObjectName("callButton")
        self._call_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._call_btn.clicked.connect(self._on_call)
        btn_row.addWidget(self._call_btn)

        self._rename_btn = QPushButton("✏️  Rename")
        self._rename_btn.setObjectName("generateButton")
        self._rename_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._rename_btn.clicked.connect(self._on_rename)
        btn_row.addWidget(self._rename_btn)

        self._copy_btn = QPushButton("📋  Copy address")
        self._copy_btn.setObjectName("copyButton")
        self._copy_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._copy_btn.clicked.connect(self._on_copy)
        btn_row.addWidget(self._copy_btn)

        self._remove_btn = QPushButton("🗑️  Remove")
        self._remove_btn.setObjectName("hangupButton")
        self._remove_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._remove_btn.clicked.connect(self._on_remove)
        btn_row.addWidget(self._remove_btn)

        btn_row.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setObjectName("generateButton")
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)

        root.addLayout(btn_row)

    # ── Data ───────────────────────────────────────────────────────────

    def _reload(self) -> None:
        """Rebuild the list from the contact store."""
        self._list.clear()
        contacts = self._list_contacts()
        for contact in contacts:
            addresses = contact.get("addresses", [])
            name = contact.get("name", "")
            primary = addresses[0] if addresses else "?"
            label_name = name if name else "(unnamed)"
            extra = f"  +{len(addresses) - 1} more" if len(addresses) > 1 else ""
            short = primary if len(primary) <= 24 else primary[:10] + "…" + primary[-6:]
            item = QListWidgetItem(f"{label_name}\n{short}{extra}")
            item.setData(Qt.ItemDataRole.UserRole, contact)
            tooltip = "\n".join(addresses)
            if name:
                tooltip = f"{name}\n{tooltip}"
            item.setToolTip(tooltip)
            self._list.addItem(item)

        has_contacts = self._list.count() > 0
        self._empty_label.setVisible(not has_contacts)
        self._list.setVisible(has_contacts)
        self._on_selection_changed()

    def _selected_contact(self) -> Optional[dict]:
        items = self._list.selectedItems()
        if not items:
            return None
        return items[0].data(Qt.ItemDataRole.UserRole)

    def _selected_address(self) -> Optional[str]:
        contact = self._selected_contact()
        if not contact:
            return None
        addresses = contact.get("addresses", [])
        return addresses[0] if addresses else None

    # ── Slots ──────────────────────────────────────────────────────────

    def _on_selection_changed(self) -> None:
        has_sel = self._selected_contact() is not None
        self._call_btn.setEnabled(has_sel)
        self._rename_btn.setEnabled(has_sel)
        self._copy_btn.setEnabled(has_sel)
        self._remove_btn.setEnabled(has_sel)

    def _on_call(self) -> None:
        address = self._selected_address()
        if not address:
            return
        log.info("ContactsDialog: dialing selected contact")
        self.call_requested.emit(address)
        self.accept()

    def _on_rename(self) -> None:
        contact = self._selected_contact()
        if not contact:
            return
        address = (contact.get("addresses") or [None])[0]
        if not address:
            return
        current = contact.get("name", "")
        new_name, ok = QInputDialog.getText(
            self, "Rename contact", "Contact name:", text=current
        )
        if ok:
            self._rename_contact(address, new_name.strip())
            self._reload()

    def _on_copy(self) -> None:
        address = self._selected_address()
        if not address:
            return
        QGuiApplication.clipboard().setText(address)
        self._copy_btn.setText("✅  Copied!")
        from PySide6.QtCore import QTimer
        QTimer.singleShot(1500, lambda: self._copy_btn.setText("📋  Copy address"))

    def _on_remove(self) -> None:
        contact = self._selected_contact()
        if not contact:
            return
        addresses = contact.get("addresses", [])
        if not addresses:
            return
        name = contact.get("name", "") or "(unnamed)"
        n_addr = len(addresses)
        detail = (
            f"This contact has {n_addr} known addresses; all of them will be "
            "forgotten."
            if n_addr > 1
            else "This address will be forgotten."
        )
        confirm = QMessageBox(self)
        confirm.setWindowTitle("Remove contact")
        confirm.setIcon(QMessageBox.Icon.Warning)
        confirm.setText(f"Remove “{name}” from your contacts?")
        confirm.setInformativeText(
            f"{detail}\n\nNote: if they call you again, they will be pinned "
            "anew as a fresh contact."
        )
        confirm.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        confirm.setDefaultButton(QMessageBox.StandardButton.No)
        if confirm.exec() != QMessageBox.StandardButton.Yes:
            return
        removed = self._remove_contact(addresses[0])
        log.info("ContactsDialog: removed contact (%d address(es))", removed)
        self._reload()

