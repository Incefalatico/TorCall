"""
TorCall cryptographic primitives.

Provides X25519 key exchange and AES-256-GCM authenticated encryption
for end-to-end encrypted voice packets.

Usage::

    priv, pub = generate_keypair()
    shared = derive_shared_key(my_private, peer_public)
    ct = encrypt(shared, plaintext, make_nonce(seq))
    pt = decrypt(shared, ct, make_nonce(seq))
"""

from __future__ import annotations

import os
import struct
import time
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

from torcall.utils.config import X25519_KEY_SIZE, AES_NONCE_SIZE
from torcall.utils.logger import log


# ── Key generation ────────────────────────────────────────────────────

def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate an ephemeral X25519 key pair.

    Returns:
        (private_key_bytes, public_key_bytes) — both 32 bytes.
    """
    private = X25519PrivateKey.generate()
    private_bytes = private.private_bytes_raw()
    public_bytes = private.public_key().public_bytes_raw()
    log.debug("Generated X25519 keypair (pub=%s…)", public_bytes[:4].hex())
    return private_bytes, public_bytes


# ── Key exchange ──────────────────────────────────────────────────────

def _ecdh(my_private: bytes, peer_public: bytes) -> bytes:
    """Run the raw X25519 ECDH and return the shared secret (32 bytes)."""
    if len(my_private) != X25519_KEY_SIZE:
        raise ValueError(f"Private key must be {X25519_KEY_SIZE} bytes, got {len(my_private)}")
    if len(peer_public) != X25519_KEY_SIZE:
        raise ValueError(f"Peer public key must be {X25519_KEY_SIZE} bytes, got {len(peer_public)}")
    private_key = X25519PrivateKey.from_private_bytes(my_private)
    public_key = X25519PublicKey.from_public_bytes(peer_public)
    return private_key.exchange(public_key)


def derive_shared_key(my_private: bytes, peer_public: bytes) -> bytes:
    """
    Perform X25519 ECDH and derive a single 32-byte symmetric key.

    .. warning::
        Both peers derive the *same* key here.  Using it to encrypt in
        both directions reuses GCM nonces (both sides start their packet
        counter at 0), which is catastrophic for AES-GCM.  Prefer
        :func:`derive_session_keys` for real bidirectional traffic.  This
        function is kept for key-agreement tests and tooling.

    Args:
        my_private:  Our private key (32 bytes raw).
        peer_public: Peer's public key (32 bytes raw).

    Returns:
        32-byte derived key suitable for AES-256-GCM.
    """
    shared_secret = _ecdh(my_private, peer_public)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"torcall-voice-e2e-v1",
    ).derive(shared_secret)

    log.debug("Derived shared key from ECDH (key=%s…)", derived[:4].hex())
    return derived


def derive_session_keys(my_private: bytes, peer_public: bytes, is_caller: bool) -> tuple[bytes, bytes]:
    """
    Derive two *directional* AES-256-GCM keys from an X25519 ECDH exchange.

    The shared secret is expanded with HKDF-SHA256 into 64 bytes, split
    into a caller→callee key and a callee→caller key.  Each direction
    therefore uses an independent key, so the per-call nonce counters
    (which both start at 0) never collide on the same key.

    Args:
        my_private:  Our private key (32 bytes raw).
        peer_public: Peer's public key (32 bytes raw).
        is_caller:   True if we initiated the call (CALL_REQUEST side),
                     False if we answered it (CALL_ACCEPT side).

    Returns:
        ``(send_key, recv_key)`` — two distinct 32-byte keys.
    """
    shared_secret = _ecdh(my_private, peer_public)
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"torcall-voice-e2e-v2-directional",
    ).derive(shared_secret)

    key_caller_to_callee = okm[:32]
    key_callee_to_caller = okm[32:]

    if is_caller:
        send_key, recv_key = key_caller_to_callee, key_callee_to_caller
    else:
        send_key, recv_key = key_callee_to_caller, key_caller_to_callee

    log.debug(
        "Derived directional keys (caller=%s, send=%s… recv=%s…)",
        is_caller, send_key[:4].hex(), recv_key[:4].hex(),
    )
    return send_key, recv_key


# ── Long-term identity (Ed25519 signatures) ──────────────────────────

# Domain-separation prefix so a handshake signature can never be replayed
# as a signature over some other protocol message.
_HANDSHAKE_CONTEXT = b"torcall-handshake-id-v1:"
# v2 binds a per-call freshness nonce (timestamp + random) so a captured
# handshake can't be replayed later to impersonate an identity.
_HANDSHAKE_CONTEXT_V2 = b"torcall-handshake-id-v2:"
# v3 additionally binds the sender's advertised .onion address, so a peer
# that learns the address only from the (signed) handshake — e.g. the
# callee, whose socket sees only loopback — can trust it as much as the
# identity key itself.
_HANDSHAKE_CONTEXT_V3 = b"torcall-handshake-id-v3:"

# Nonce layout: 8-byte big-endian Unix timestamp (seconds) + 8 random bytes.
HANDSHAKE_NONCE_LEN = 16
# A handshake is rejected if its timestamp is further than this from "now"
# (in either direction, to tolerate modest clock skew).
_HANDSHAKE_MAX_SKEW_S = 120


def make_handshake_nonce() -> bytes:
    """Build a fresh handshake nonce: ``timestamp(8) + random(8)``.

    The timestamp lets the verifier bound the replay window; the random
    tail makes each nonce unique even within the same second.
    """
    return struct.pack(">Q", int(time.time())) + os.urandom(8)


def handshake_nonce_is_fresh(nonce: bytes, max_skew_s: int = _HANDSHAKE_MAX_SKEW_S) -> bool:
    """Return True if *nonce*'s embedded timestamp is within *max_skew_s*
    seconds of the current time."""
    if len(nonce) != HANDSHAKE_NONCE_LEN:
        return False
    (ts,) = struct.unpack(">Q", nonce[:8])
    return abs(int(time.time()) - ts) <= max_skew_s


def generate_identity_keypair() -> tuple[bytes, bytes]:
    """
    Generate a long-term Ed25519 identity key pair.

    Unlike the ephemeral X25519 keys (fresh per call), this pair is meant
    to persist on disk so a contact can recognise us across calls.

    Returns:
        ``(private_key_bytes, public_key_bytes)`` — both 32 bytes raw.
    """
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes_raw()
    public_bytes = private.public_key().public_bytes_raw()
    log.debug("Generated Ed25519 identity (pub=%s…)", public_bytes[:4].hex())
    return private_bytes, public_bytes


def identity_public_from_private(private_bytes: bytes) -> bytes:
    """Recover the Ed25519 public key from a 32-byte private key."""
    if len(private_bytes) != 32:
        raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(private_bytes)}")
    private = Ed25519PrivateKey.from_private_bytes(private_bytes)
    return private.public_key().public_bytes_raw()


def sign_handshake(
    identity_private: bytes,
    ephemeral_public: bytes,
    nonce: Optional[bytes] = None,
    onion_address: Optional[str] = None,
) -> bytes:
    """
    Sign an ephemeral X25519 public key with our long-term Ed25519 key.

    Binding the per-call ephemeral key to a persistent identity lets the
    peer verify that whoever controls the ``.onion`` address also controls
    the recognised identity key — the basis for contact pinning (TOFU).

    When *nonce* is supplied the freshness-bound v2 form is signed
    (``context_v2 + nonce + ephemeral``); supplying *onion_address* as well
    yields the v3 form (``context_v3 + nonce + ephemeral + addr``), which
    additionally binds the sender's advertised address.  With neither, the
    legacy v1 form (``context_v1 + ephemeral``) is produced for backward
    compatibility.

    Args:
        identity_private: Our 32-byte Ed25519 private key.
        ephemeral_public: The 32-byte X25519 public key sent this call.
        nonce:            Optional 16-byte freshness nonce (see
                          :func:`make_handshake_nonce`).
        onion_address:    Optional ``.onion`` address to bind into the
                          signature (requires *nonce*).

    Returns:
        A 64-byte Ed25519 signature.
    """
    if len(identity_private) != 32:
        raise ValueError(f"Ed25519 private key must be 32 bytes, got {len(identity_private)}")
    private = Ed25519PrivateKey.from_private_bytes(identity_private)
    if nonce is None:
        return private.sign(_HANDSHAKE_CONTEXT + ephemeral_public)
    if len(nonce) != HANDSHAKE_NONCE_LEN:
        raise ValueError(f"Handshake nonce must be {HANDSHAKE_NONCE_LEN} bytes")
    if onion_address is None:
        return private.sign(_HANDSHAKE_CONTEXT_V2 + nonce + ephemeral_public)
    return private.sign(
        _HANDSHAKE_CONTEXT_V3 + nonce + ephemeral_public
        + onion_address.encode("utf-8")
    )


def verify_handshake(
    identity_public: bytes,
    ephemeral_public: bytes,
    signature: bytes,
    nonce: Optional[bytes] = None,
    onion_address: Optional[str] = None,
) -> bool:
    """
    Verify an Ed25519 handshake signature.

    When *nonce* is supplied the v2 form is checked (and the nonce's
    embedded timestamp must be fresh); supplying *onion_address* as well
    checks the v3 form, which binds that address into the signature.
    Otherwise the legacy v1 form is verified.

    Args:
        identity_public:  Peer's claimed 32-byte Ed25519 public key.
        ephemeral_public: The 32-byte X25519 public key they sent.
        signature:        The 64-byte signature to check.
        nonce:            Optional 16-byte freshness nonce.
        onion_address:    Optional ``.onion`` address that must match the
                          one bound into the signature (requires *nonce*).

    Returns:
        True if the signature is valid (and fresh, for v2/v3), False
        otherwise.  Never raises on bad input — it's treated as a failed
        check.
    """
    if len(identity_public) != 32 or len(signature) != 64:
        return False
    if nonce is None:
        signed = _HANDSHAKE_CONTEXT + ephemeral_public
    else:
        if not handshake_nonce_is_fresh(nonce):
            log.warning("Handshake nonce is stale or malformed — rejecting")
            return False
        if onion_address is None:
            signed = _HANDSHAKE_CONTEXT_V2 + nonce + ephemeral_public
        else:
            signed = (
                _HANDSHAKE_CONTEXT_V3 + nonce + ephemeral_public
                + onion_address.encode("utf-8")
            )
    try:
        public = Ed25519PublicKey.from_public_bytes(identity_public)
        public.verify(signature, signed)
        return True
    except (InvalidSignature, ValueError):
        return False


def fingerprint(identity_public: bytes, groups: int = 8) -> str:
    """
    Produce a human-readable fingerprint of an identity public key.

    Used to display and compare contact identities (e.g. on first contact
    or when a pinned key changes).  Returns a colon-separated hex string
    of the first *groups* bytes, e.g. ``"a1:b2:c3:…"``.
    """
    raw = identity_public[:groups]
    return ":".join(f"{b:02x}" for b in raw)


# ── Short Authentication String (MITM detection) ─────────────────────

# A small PGP-style word list.  The exact words do not matter for
# security — what matters is that both peers map the same bytes to the
# same easy-to-read tokens, so they can compare them out loud.
_SAS_WORDS = (
    "alpha", "bravo", "canyon", "delta", "ember", "forest", "ginger", "harbor",
    "igloo", "jaguar", "kettle", "lemon", "mango", "nectar", "orbit", "pepper",
    "quartz", "river", "sierra", "tango", "umbra", "violet", "willow", "xenon",
    "yonder", "zephyr", "anchor", "basil", "cobalt", "dynamo", "echo", "falcon",
    "granite", "hazel", "ivory", "jasmine", "koala", "lunar", "marble", "nimbus",
    "onyx", "pixel", "quasar", "raven", "saffron", "topaz", "ultra", "velvet",
    "walnut", "xander", "yodel", "zenith", "amber", "bronze", "cedar", "denim",
    "elm", "fable", "glacier", "harmony", "indigo", "juniper", "kismet", "lotus",
)


def compute_sas(public_a: bytes, public_b: bytes, words: int = 4) -> str:
    """
    Derive a Short Authentication String from both handshake public keys.

    The SAS is a human-comparable code (a few words) that both peers
    compute independently from the *same* inputs.  After the call
    connects, the two parties read it aloud: if an active man-in-the-
    middle sat between them, each side negotiated a different key pair
    with the attacker, so the strings will not match.  Ephemeral X25519
    alone protects against passive eavesdroppers but not an active MITM
    relaying the handshake — the SAS closes that gap with a quick verbal
    check.

    The keys are sorted before hashing so both ends produce the same
    result regardless of who is caller and who is callee.

    Args:
        public_a: One party's X25519 public key (32 bytes).
        public_b: The other party's X25519 public key (32 bytes).
        words:    How many words the SAS should contain.

    Returns:
        A space-separated lowercase word string, e.g. ``"river ember koala tango"``.
    """
    lo, hi = sorted((public_a, public_b))
    digest = HKDF(
        algorithm=hashes.SHA256(),
        length=words,
        salt=None,
        info=b"torcall-sas-v1",
    ).derive(lo + hi)
    return " ".join(_SAS_WORDS[b % len(_SAS_WORDS)] for b in digest)


# ── Traffic-analysis padding ──────────────────────────────────────────

def pad_frame(data: bytes, block: int) -> bytes:
    """
    Length-prefix and pad *data* to a multiple of *block* bytes.

    Opus is variable-bitrate, so the size of each encrypted audio frame
    leaks whether the speaker is talking or silent.  By padding every
    frame up to the next multiple of *block*, all frames collapse onto a
    small set of fixed sizes and that timing/volume signal disappears.

    The layout (before encryption) is::

        ┌────────────┬──────────────┬───────────────┐
        │ len  2B BE │ data (len B) │ zero padding  │
        └────────────┴──────────────┴───────────────┘

    Args:
        data:  Plaintext frame (e.g. an Opus packet).  Max 65535 bytes.
        block: Quantisation block size (must be ≥ 1).

    Returns:
        Padded buffer whose length is a multiple of *block*.
    """
    if block < 1:
        raise ValueError("Padding block size must be ≥ 1")
    if len(data) > 0xFFFF:
        raise ValueError("Frame too large to pad (max 65535 bytes)")
    body = struct.pack(">H", len(data)) + data
    remainder = len(body) % block
    if remainder:
        body += b"\x00" * (block - remainder)
    return body


def unpad_frame(padded: bytes) -> bytes:
    """
    Reverse :func:`pad_frame`, recovering the original data.

    Args:
        padded: The padded buffer produced by :func:`pad_frame`.

    Returns:
        The original unpadded data.

    Raises:
        ValueError: If the buffer is too short or the length prefix is
            inconsistent with the buffer size.
    """
    if len(padded) < 2:
        raise ValueError("Padded frame too short")
    (length,) = struct.unpack(">H", padded[:2])
    if 2 + length > len(padded):
        raise ValueError("Padded frame length prefix exceeds buffer")
    return padded[2 : 2 + length]


# ── Nonce construction ────────────────────────────────────────────────

def make_nonce(counter: int) -> bytes:
    """
    Build a 12-byte GCM nonce from a monotonic counter.

    The counter is encoded as an 8-byte big-endian integer and
    zero-padded to 12 bytes on the left.

    Args:
        counter: Packet sequence number (non-negative).

    Returns:
        12-byte nonce.
    """
    return b"\x00" * 4 + struct.pack(">Q", counter)


# ── Symmetric encryption ─────────────────────────────────────────────

def encrypt(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Args:
        key:       32-byte symmetric key.
        plaintext: Data to encrypt.
        nonce:     12-byte nonce (must be unique per key).

    Returns:
        Ciphertext with appended 16-byte authentication tag.
    """
    aes = AESGCM(key)
    return aes.encrypt(nonce, plaintext, associated_data=None)


def decrypt(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    """
    Decrypt *ciphertext* with AES-256-GCM.

    Args:
        key:        32-byte symmetric key.
        ciphertext: Data to decrypt (includes 16-byte tag).
        nonce:      12-byte nonce used during encryption.

    Returns:
        Decrypted plaintext.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, associated_data=None)


# ── At-rest encryption (passphrase-protected secrets) ────────────────

# Magic headers so we can recognise our own blobs and version the format.
#
#   TCV1 (legacy): b"TCV1" | salt(16) | nonce(12) | AES-256-GCM ct+tag
#                  scrypt fixed at N=2^15.
#   TCV2 (current): b"TCV2" | log2N(1) | salt(16) | nonce(12) | ct+tag
#                  scrypt cost is self-describing so it can be raised again
#                  later without breaking older files.
#
_VAULT_MAGIC = b"TCV1"          # legacy magic (read-only path)
_VAULT_MAGIC_V2 = b"TCV2"       # current magic (written by encrypt_at_rest)
_SCRYPT_N_LEGACY = 2 ** 15      # cost used by TCV1 blobs
_SCRYPT_LOG2_N = 17             # current cost: N = 2^17 (~hundreds of ms)
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_SIZE = 16


def _derive_passphrase_key(passphrase: str, salt: bytes, n: int) -> bytes:
    """Stretch a passphrase into a 32-byte key with scrypt at cost *n*."""
    kdf = Scrypt(salt=salt, length=32, n=n, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_at_rest(passphrase: str, plaintext: bytes) -> bytes:
    """
    Encrypt *plaintext* under a passphrase for storage on disk.

    The output is a self-describing binary blob (current TCV2 form)::

        b"TCV2" | log2N(1) | salt(16) | nonce(12) | AES-256-GCM ciphertext+tag

    A fresh random salt and nonce are generated on every call, so
    encrypting the same data twice yields different blobs.  The
    passphrase is stretched with scrypt (N=2^17) to resist brute-force
    attacks on weak passphrases; the cost factor is stored in the header
    so it can be raised again in future without breaking old files.

    Args:
        passphrase: User secret.  An empty passphrase is rejected.
        plaintext:  Data to protect.

    Returns:
        Encrypted blob suitable for writing to a file.
    """
    if not passphrase:
        raise ValueError("Refusing to encrypt with an empty passphrase")
    salt = os.urandom(_SALT_SIZE)
    nonce = os.urandom(AES_NONCE_SIZE)
    # Header (magic + cost) is authenticated as associated data so the
    # stored scrypt parameter can't be tampered with to weaken decryption.
    header = _VAULT_MAGIC_V2 + bytes([_SCRYPT_LOG2_N])
    key = _derive_passphrase_key(passphrase, salt, 2 ** _SCRYPT_LOG2_N)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=header)
    finally:
        key = wipe_bytes(key)
    return header + salt + nonce + ciphertext


def decrypt_at_rest(passphrase: str, blob: bytes) -> bytes:
    """
    Decrypt a blob produced by :func:`encrypt_at_rest`.

    Transparently handles both the current TCV2 form (self-describing
    scrypt cost) and legacy TCV1 blobs (fixed N=2^15) so existing
    identity/contact files stay readable.

    Args:
        passphrase: The same passphrase used to encrypt.
        blob:       The stored blob.

    Returns:
        The original plaintext.

    Raises:
        ValueError: If the blob is malformed / not a TorCall vault.
        cryptography.exceptions.InvalidTag: If the passphrase is wrong or
            the data was tampered with.
    """
    magic = blob[:4]
    if magic == _VAULT_MAGIC_V2:
        # b"TCV2" | log2N(1) | salt(16) | nonce(12) | ct
        min_len = 4 + 1 + _SALT_SIZE + AES_NONCE_SIZE
        if len(blob) < min_len:
            raise ValueError("Not a valid TorCall encrypted blob")
        log2n = blob[4]
        if not (1 <= log2n <= 31):
            raise ValueError("Invalid scrypt cost in vault header")
        header = blob[:5]
        salt = blob[5 : 5 + _SALT_SIZE]
        nonce = blob[5 + _SALT_SIZE : min_len]
        ciphertext = blob[min_len:]
        n = 2 ** log2n
        associated = header
    elif magic == _VAULT_MAGIC:
        # Legacy TCV1: b"TCV1" | salt(16) | nonce(12) | ct, N fixed.
        min_len = 4 + _SALT_SIZE + AES_NONCE_SIZE
        if len(blob) < min_len:
            raise ValueError("Not a valid TorCall encrypted blob")
        salt = blob[4 : 4 + _SALT_SIZE]
        nonce = blob[4 + _SALT_SIZE : min_len]
        ciphertext = blob[min_len:]
        n = _SCRYPT_N_LEGACY
        associated = _VAULT_MAGIC
    else:
        raise ValueError("Not a valid TorCall encrypted blob")
    key = _derive_passphrase_key(passphrase, salt, n)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data=associated)
    finally:
        key = wipe_bytes(key)


def is_vault_blob(blob: bytes) -> bool:
    """Return True if *blob* looks like an :func:`encrypt_at_rest` output."""
    return blob[:4] in (_VAULT_MAGIC_V2, _VAULT_MAGIC)


# ── Memory hygiene ────────────────────────────────────────────────────

def wipe_bytes(buffer) -> None:
    """
    Best-effort overwrite of a mutable byte buffer's contents with zeros.

    Python cannot guarantee secrets are erased from memory — immutable
    ``bytes`` may have been copied by the interpreter, and the GC moves
    objects around — but zeroing a ``bytearray`` we own removes the most
    obvious lingering copy.  Always rebind the variable to ``None`` after
    calling this.

    Accepts a ``bytearray`` (overwritten in place) and ignores anything
    immutable, so callers can pass either without branching.
    """
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0
    return None
