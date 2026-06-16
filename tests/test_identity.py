import json

import pytest

from torcall.core import identity as identity_mod
from torcall.core.identity import Identity, ContactStore
from torcall.core.crypto import generate_identity_keypair, is_vault_blob


@pytest.fixture
def temp_paths(tmp_path, monkeypatch):
    """Redirect identity/contacts files to a temp dir and clear passphrase."""
    sign_file = tmp_path / "id_ed25519"
    contacts_file = tmp_path / "contacts"
    monkeypatch.setattr(identity_mod, "IDENTITY_SIGN_FILE", str(sign_file))
    monkeypatch.setattr(identity_mod, "CONTACTS_FILE", str(contacts_file))
    monkeypatch.delenv("TORCALL_PASSPHRASE", raising=False)
    return sign_file, contacts_file


def test_identity_creates_and_persists(temp_paths):
    sign_file, _ = temp_paths
    ident = Identity()
    ident.load_or_create()
    assert len(ident.private_key) == 32
    assert len(ident.public_key) == 32
    assert sign_file.exists()

    # A second Identity loads the same key from disk
    ident2 = Identity()
    ident2.load_or_create()
    assert ident2.private_key == ident.private_key
    assert ident2.public_key == ident.public_key


def test_identity_encrypted_at_rest_with_passphrase(temp_paths, monkeypatch):
    sign_file, _ = temp_paths
    monkeypatch.setenv("TORCALL_PASSPHRASE", "hunter2")
    ident = Identity()
    ident.load_or_create()
    raw = sign_file.read_bytes()
    assert is_vault_blob(raw)
    assert ident.private_key not in raw

    # Reload with the same passphrase recovers the key
    ident2 = Identity()
    ident2.load_or_create()
    assert ident2.private_key == ident.private_key


def test_contacts_tofu_flow(temp_paths):
    store = ContactStore()
    store.load()
    _, pub_a = generate_identity_keypair()
    _, pub_b = generate_identity_keypair()

    assert store.check("alice.onion", pub_a) == "new"
    assert store.check("alice.onion", pub_a) == "match"
    assert store.check("alice.onion", pub_b) == "mismatch"

    # Re-pin accepts the new key
    store.repin("alice.onion", pub_b)
    assert store.check("alice.onion", pub_b) == "match"


def test_contacts_persist_across_instances(temp_paths):
    _, pub = generate_identity_keypair()
    store = ContactStore()
    store.load()
    store.check("bob.onion", pub)

    store2 = ContactStore()
    store2.load()
    assert store2.check("bob.onion", pub) == "match"
    assert store2.get("bob.onion")["key"] == pub.hex()


def test_contacts_set_name(temp_paths):
    _, pub = generate_identity_keypair()
    store = ContactStore()
    store.load()
    store.check("carol.onion", pub)
    store.set_name("carol.onion", "Carol")
    assert store.get("carol.onion")["name"] == "Carol"


def test_contacts_recognised_across_addresses(temp_paths):
    """Same identity reached from a new .onion is recognised, not treated
    as a stranger."""
    _, pub = generate_identity_keypair()
    store = ContactStore()
    store.load()

    assert store.check("old.onion", pub) == "new"
    store.set_name("old.onion", "Dave")

    # Dave rotates his hidden service: new address, same identity key
    assert store.check("new.onion", pub) == "known_new_address"
    # The name follows the identity to the new address
    assert store.name_for_key(pub.hex()) == "Dave"
    assert store.get("new.onion")["name"] == "Dave"


def test_contacts_rename_syncs_all_addresses(temp_paths):
    """Renaming propagates to every address sharing the same identity."""
    _, pub = generate_identity_keypair()
    store = ContactStore()
    store.load()
    store.check("addr1.onion", pub)
    store.check("addr2.onion", pub)  # known_new_address

    store.set_name("addr2.onion", "Eve")
    assert store.get("addr1.onion")["name"] == "Eve"
    assert store.get("addr2.onion")["name"] == "Eve"


def test_all_contacts_groups_by_identity(temp_paths):
    """all_contacts() collapses multiple addresses of one identity into a
    single entry."""
    _, pub_a = generate_identity_keypair()
    _, pub_b = generate_identity_keypair()
    store = ContactStore()
    store.load()
    store.check("a1.onion", pub_a)
    store.check("a2.onion", pub_a)  # same identity, new address
    store.check("b1.onion", pub_b)

    contacts = store.all_contacts()
    assert len(contacts) == 2  # two identities, not three addresses
    by_key = {c["key"]: c for c in contacts}
    assert sorted(by_key[pub_a.hex()]["addresses"]) == ["a1.onion", "a2.onion"]
    assert by_key[pub_b.hex()]["addresses"] == ["b1.onion"]


def test_remove_contact_drops_all_sibling_addresses(temp_paths):
    """Removing a contact forgets every address sharing its identity key,
    while leaving other contacts intact."""
    _, pub_a = generate_identity_keypair()
    _, pub_b = generate_identity_keypair()
    store = ContactStore()
    store.load()
    store.check("a1.onion", pub_a)
    store.check("a2.onion", pub_a)  # same identity, new address
    store.check("b1.onion", pub_b)

    removed = store.remove("a1.onion")
    assert removed == 2  # both of A's addresses gone
    assert store.get("a1.onion") is None
    assert store.get("a2.onion") is None
    # B is untouched
    assert store.get("b1.onion") is not None
    assert len(store.all_contacts()) == 1


def test_remove_contact_persists_across_instances(temp_paths):
    """A removal is written to disk, so a reloaded store stays empty."""
    _, pub = generate_identity_keypair()
    store = ContactStore()
    store.load()
    store.check("gone.onion", pub)
    store.remove("gone.onion")

    reloaded = ContactStore()
    reloaded.load()
    assert reloaded.get("gone.onion") is None


def test_remove_unknown_contact_is_noop(temp_paths):
    """Removing an address that isn't pinned returns 0 and changes nothing."""
    store = ContactStore()
    store.load()
    assert store.remove("nope.onion") == 0