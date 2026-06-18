"""
TorCall long-term identity and contact pinning (TOFU).

This module ties together two privacy features:

* **Persistent identity** — a long-term Ed25519 key pair that survives
  across calls.  Every call we sign the ephemeral X25519 handshake key
  with it, so a peer can confirm that the same identity is on the other
  end each time, independently of the ``.onion`` address.

* **Trust-on-first-use (TOFU) pinning** — the first time we successfully
  verify a peer's identity we *pin* it against a chosen name/address.  If
  that key ever changes for the same contact, we surface a warning, the
  same way SSH does for host keys.

Both the identity key and the contacts database are stored under the
per-user identity directory and encrypted at rest with
:func:`torcall.core.crypto.encrypt_at_rest` whenever a passphrase
(``TORCALL_PASSPHRASE``) is configured.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from torcall.core.crypto import (
    generate_identity_keypair,
    identity_public_from_private,
    encrypt_at_rest,
    decrypt_at_rest,
    is_vault_blob,
    fingerprint,
)
from torcall.utils.config import (
    IDENTITY_SIGN_FILE,
    CONTACTS_FILE,
    get_passphrase,
)
from torcall.utils.logger import log


# ── On-disk helpers ───────────────────────────────────────────────────

def _write_secret(path: str, data: bytes) -> None:
    """Write *data* to *path*, encrypting at rest when a passphrase is set."""
    passphrase = get_passphrase()
    if passphrase:
        blob = encrypt_at_rest(passphrase, data)
        with open(path, "wb") as fh:
            fh.write(blob)
    else:
        log.warning(
            "No TORCALL_PASSPHRASE set — %s stored in PLAINTEXT",
            os.path.basename(path),
        )
        with open(path, "wb") as fh:
            fh.write(data)


def _read_secret(path: str) -> Optional[bytes]:
    """Read and (if needed) decrypt *path*.  Returns None if unavailable."""
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        raw = fh.read()
    if is_vault_blob(raw):
        passphrase = get_passphrase()
        if not passphrase:
            log.error(
                "%s is encrypted but no TORCALL_PASSPHRASE is set",
                os.path.basename(path),
            )
            return None
        return decrypt_at_rest(passphrase, raw)
    return raw  # legacy plaintext


# ── Persistent identity ───────────────────────────────────────────────

class Identity:
    """The local long-term Ed25519 identity.

    Lazily loads an existing key from disk, or generates and persists a
    fresh one on first use.
    """

    def __init__(self) -> None:
        self._private: Optional[bytes] = None
        self._public: Optional[bytes] = None

    def load_or_create(self) -> None:
        """Load the identity key from disk, creating it if absent."""
        try:
            data = _read_secret(IDENTITY_SIGN_FILE)
        except Exception:
            log.exception("Failed to read identity key — generating a new one")
            data = None

        if data and len(data) == 32:
            self._private = data
            self._public = identity_public_from_private(data)
            log.info("Loaded identity %s", self.fingerprint)
            return

        # Generate and persist a new identity
        self._private, self._public = generate_identity_keypair()
        try:
            _write_secret(IDENTITY_SIGN_FILE, self._private)
            log.info("Created new identity %s", self.fingerprint)
        except OSError:
            log.exception("Failed to persist new identity (continuing in-memory)")

    @property
    def private_key(self) -> bytes:
        if self._private is None:
            self.load_or_create()
        assert self._private is not None
        return self._private

    @property
    def public_key(self) -> bytes:
        if self._public is None:
            self.load_or_create()
        assert self._public is not None
        return self._public

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)


# ── Contact pinning (TOFU) ────────────────────────────────────────────

class ContactStore:
    """Trust-on-first-use store mapping a peer label → pinned identity key.

    The store is keyed by the peer's ``.onion`` address (the stable
    handle the user dials).  Each entry records the pinned Ed25519 public
    key (hex) plus an optional human name.
    """

    def __init__(self) -> None:
        # address -> {"key": hex, "name": str}
        self._contacts: dict[str, dict] = {}

    def load(self) -> None:
        """Load pinned contacts from disk."""
        try:
            data = _read_secret(CONTACTS_FILE)
        except Exception:
            log.exception("Failed to read contacts store — starting empty")
            return
        if not data:
            return
        try:
            self._contacts = json.loads(data.decode("utf-8"))
            log.info("Loaded %d pinned contact(s)", len(self._contacts))
        except (ValueError, UnicodeDecodeError):
            log.exception("Contacts store is corrupt — starting empty")
            self._contacts = {}

    def _save(self) -> None:
        try:
            data = json.dumps(self._contacts).encode("utf-8")
            _write_secret(CONTACTS_FILE, data)
        except OSError:
            log.exception("Failed to save contacts store")

    def check(self, address: str, identity_public: bytes) -> str:
        """Compare *identity_public* against the pinned identity for *address*.

        Recognition is keyed primarily by the long-term Ed25519 *identity*,
        because ``.onion`` addresses are ephemeral and can be regenerated by
        the peer.  The address is just a convenient handle.

        Returns one of:

        * ``"new"``               — first time we see this identity *and*
          this address (now pinned).
        * ``"match"``             — same identity already pinned to this
          exact address.
        * ``"known_new_address"`` — we recognise this identity from a
          *different* address (the peer rotated their ``.onion``).  The new
          address is pinned to the same identity/name.
        * ``"mismatch"``          — this address was pinned to a *different*
          identity (possible MITM or the peer rotated their identity key).
        """
        key_hex = identity_public.hex()
        entry = self._contacts.get(address)

        if entry is not None:
            if entry.get("key") == key_hex:
                return "match"
            log.warning(
                "Identity MISMATCH for %s: pinned %s… got %s…",
                address, entry.get("key", "")[:8], key_hex[:8],
            )
            return "mismatch"

        # Address unknown — is this identity already pinned elsewhere?
        for other_addr, other in self._contacts.items():
            if other.get("key") == key_hex:
                name = other.get("name", "")
                self._contacts[address] = {"key": key_hex, "name": name}
                self._save()
                log.info(
                    "Known contact %s reached us from a new address",
                    fingerprint(identity_public),
                )
                return "known_new_address"

        # Genuinely new identity
        self._contacts[address] = {"key": key_hex, "name": ""}
        self._save()
        log.info("Pinned new contact %s (%s)", address, fingerprint(identity_public))
        return "new"

    def repin(self, address: str, identity_public: bytes) -> None:
        """Forcefully replace the pinned key for *address* (after the user
        accepts an identity change)."""
        name = self._contacts.get(address, {}).get("name", "")
        self._contacts[address] = {"key": identity_public.hex(), "name": name}
        self._save()
        log.info("Re-pinned contact %s", address)

    def set_name(self, address: str, name: str) -> None:
        """Assign a human-readable name to *address*.

        The name is propagated to every address that shares the same
        identity key, so renaming a contact who rotated their ``.onion``
        keeps every known address in sync.
        """
        entry = self._contacts.get(address)
        if entry is None:
            return
        key_hex = entry.get("key", "")
        for other in self._contacts.values():
            if other.get("key") == key_hex:
                other["name"] = name
        self._save()

    def name_for_key(self, key_hex: str) -> str:
        """Return the stored name for an identity key, or empty string."""
        for entry in self._contacts.values():
            if entry.get("key") == key_hex and entry.get("name"):
                return entry["name"]
        return ""

    def remove(self, address: str) -> int:
        """Remove the contact reachable at *address* from the store.

        Because a single person may be pinned under several ``.onion``
        addresses (they rotated their address but kept their identity key),
        every address sharing the same identity key is removed together so
        the contact disappears entirely rather than partially.

        Returns the number of address entries removed.
        """
        entry = self._contacts.get(address)
        if entry is None:
            return 0
        key_hex = entry.get("key", "")
        # Collect every address bound to the same identity key.
        to_remove = [
            addr for addr, other in self._contacts.items()
            if key_hex and other.get("key") == key_hex
        ] or [address]
        for addr in to_remove:
            self._contacts.pop(addr, None)
        self._save()
        log.info("Removed contact (%d address(es))", len(to_remove))
        return len(to_remove)

    def all_contacts(self) -> list[dict]:
        """Return one entry per *known identity* for display in the address
        book.

        Contacts that share the same identity key (the same person reached
        from several ``.onion`` addresses) are collapsed into a single entry
        listing all their known addresses, most recent first.
        """
        by_key: dict[str, dict] = {}
        for addr, entry in self._contacts.items():
            key_hex = entry.get("key", "")
            if not key_hex:
                continue
            bucket = by_key.setdefault(
                key_hex,
                {"key": key_hex, "name": entry.get("name", ""), "addresses": []},
            )
            bucket["addresses"].append(addr)
            if entry.get("name") and not bucket["name"]:
                bucket["name"] = entry["name"]
        return list(by_key.values())

    def get(self, address: str) -> Optional[dict]:
        return self._contacts.get(address)
