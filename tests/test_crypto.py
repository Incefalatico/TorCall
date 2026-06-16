import pytest
from torcall.core.crypto import (
    generate_keypair,
    derive_shared_key,
    derive_session_keys,
    compute_sas,
    encrypt,
    decrypt,
    make_nonce,
    encrypt_at_rest,
    decrypt_at_rest,
    is_vault_blob,
    wipe_bytes,
    generate_identity_keypair,
    identity_public_from_private,
    sign_handshake,
    verify_handshake,
    make_handshake_nonce,
    handshake_nonce_is_fresh,
    fingerprint,
    pad_frame,
    unpad_frame,
)

def test_key_generation():
    """Verify that generate_keypair returns valid 32-byte keys."""
    priv1, pub1 = generate_keypair()
    priv2, pub2 = generate_keypair()
    
    assert len(priv1) == 32
    assert len(pub1) == 32
    assert len(priv2) == 32
    assert len(pub2) == 32
    
    # Ensure they are distinct
    assert priv1 != priv2
    assert pub1 != pub2

def test_key_exchange():
    """Verify that ECDH key exchange produces identical keys for both parties."""
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()
    
    alice_shared = derive_shared_key(alice_priv, bob_pub)
    bob_shared = derive_shared_key(bob_priv, alice_pub)
    
    assert len(alice_shared) == 32
    assert alice_shared == bob_shared

def test_encrypt_decrypt_roundtrip():
    """Verify that encryption and decryption restores the original plaintext."""
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()
    
    key = derive_shared_key(alice_priv, bob_pub)
    
    message = b"Testing TorCall voice packets encryption"
    nonce = make_nonce(42)
    
    ciphertext = encrypt(key, message, nonce)
    # Ciphertext should be longer than plaintext due to GCM authentication tag
    assert len(ciphertext) > len(message)
    
    decrypted = decrypt(key, ciphertext, nonce)
    assert decrypted == message

def test_invalid_decrypt():
    """Verify that decryption fails when keys, nonces, or data are modified."""
    from cryptography.exceptions import InvalidTag
    
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()
    key = derive_shared_key(alice_priv, bob_pub)
    
    message = b"Secret message"
    nonce = make_nonce(1)
    
    ciphertext = encrypt(key, message, nonce)
    
    # Decrypt with wrong nonce
    wrong_nonce = make_nonce(2)
    with pytest.raises(InvalidTag):
        decrypt(key, ciphertext, wrong_nonce)
        
    # Decrypt with wrong key
    wrong_key = b"w" * 32
    with pytest.raises(InvalidTag):
        decrypt(wrong_key, ciphertext, nonce)
        
    # Decrypt modified ciphertext
    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt(key, bytes(modified_ciphertext), nonce)

def test_make_nonce():
    """Verify that make_nonce produces nonces with correct size and layout."""
    nonce = make_nonce(0)
    assert len(nonce) == 12
    assert nonce == b"\x00" * 12
    
    nonce_large = make_nonce(0x0102030405060708)
    assert len(nonce_large) == 12
    assert nonce_large == b"\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08"


def test_directional_keys_match_across_peers():
    """Caller's send key must equal callee's recv key, and vice versa."""
    caller_priv, caller_pub = generate_keypair()
    callee_priv, callee_pub = generate_keypair()

    caller_send, caller_recv = derive_session_keys(caller_priv, callee_pub, is_caller=True)
    callee_send, callee_recv = derive_session_keys(callee_priv, caller_pub, is_caller=False)

    # All four keys are 32 bytes
    for k in (caller_send, caller_recv, callee_send, callee_recv):
        assert len(k) == 32

    # Cross-direction agreement
    assert caller_send == callee_recv
    assert callee_send == caller_recv

    # The two directions must use DISTINCT keys (this is what prevents
    # nonce reuse when both peers start their counter at 0).
    assert caller_send != caller_recv


def test_directional_keys_prevent_nonce_reuse():
    """Same nonce + same plaintext on opposite directions yields different ciphertext."""
    caller_priv, caller_pub = generate_keypair()
    callee_priv, callee_pub = generate_keypair()

    caller_send, _ = derive_session_keys(caller_priv, callee_pub, is_caller=True)
    callee_send, _ = derive_session_keys(callee_priv, caller_pub, is_caller=False)

    nonce = make_nonce(0)  # both peers' first packet
    plaintext = b"first audio frame"

    ct_caller = encrypt(caller_send, plaintext, nonce)
    ct_callee = encrypt(callee_send, plaintext, nonce)

    # Different keys → different ciphertext even with identical nonce+data,
    # so the catastrophic GCM nonce-reuse condition cannot occur.
    assert ct_caller != ct_callee


def test_derive_session_keys_rejects_bad_lengths():
    """Key derivation must validate input sizes."""
    priv, pub = generate_keypair()
    with pytest.raises(ValueError):
        derive_session_keys(b"too short", pub, is_caller=True)
    with pytest.raises(ValueError):
        derive_session_keys(priv, b"too short", is_caller=False)


def test_sas_is_symmetric_and_deterministic():
    """Both peers must compute the same SAS regardless of argument order."""
    _, pub_a = generate_keypair()
    _, pub_b = generate_keypair()

    sas_caller = compute_sas(pub_a, pub_b)
    sas_callee = compute_sas(pub_b, pub_a)  # order swapped

    assert sas_caller == sas_callee          # symmetric
    assert sas_caller == compute_sas(pub_a, pub_b)  # deterministic
    assert len(sas_caller.split()) == 4      # default word count


def test_sas_differs_for_different_keys():
    """A MITM negotiating different keys yields a different SAS."""
    _, pub_a = generate_keypair()
    _, pub_b = generate_keypair()
    _, pub_attacker = generate_keypair()

    legit = compute_sas(pub_a, pub_b)
    mitm = compute_sas(pub_a, pub_attacker)  # what one side would see vs an attacker

    assert legit != mitm


def test_sas_word_count_configurable():
    """The number of SAS words is configurable."""
    _, pub_a = generate_keypair()
    _, pub_b = generate_keypair()
    assert len(compute_sas(pub_a, pub_b, words=6).split()) == 6


def test_at_rest_roundtrip():
    """encrypt_at_rest / decrypt_at_rest restores the original plaintext."""
    secret = b"ED25519-V3:super-secret-hidden-service-key-material"
    blob = encrypt_at_rest("correct horse battery staple", secret)

    assert is_vault_blob(blob)
    assert secret not in blob  # plaintext must not appear in the blob
    assert decrypt_at_rest("correct horse battery staple", blob) == secret


def test_at_rest_uses_tcv2_format():
    """Newly written blobs use the self-describing TCV2 header (N=2^17)."""
    blob = encrypt_at_rest("pass", b"data")
    assert blob[:4] == b"TCV2"
    assert blob[4] == 17  # log2(N)


def test_at_rest_reads_legacy_tcv1_blob():
    """Legacy TCV1 blobs (scrypt N=2^15) remain decryptable."""
    import os as _os
    import struct  # noqa: F401  (kept for clarity / parity with prod code)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    passphrase = "legacy-pass"
    secret = b"legacy hidden service key"
    salt = _os.urandom(16)
    nonce = _os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())
    ct = AESGCM(key).encrypt(nonce, secret, associated_data=b"TCV1")
    legacy_blob = b"TCV1" + salt + nonce + ct

    assert is_vault_blob(legacy_blob)
    assert decrypt_at_rest(passphrase, legacy_blob) == secret


def test_at_rest_wrong_passphrase_fails():
    """A wrong passphrase must raise (authentication failure)."""
    from cryptography.exceptions import InvalidTag

    blob = encrypt_at_rest("right-pass", b"data")
    with pytest.raises(InvalidTag):
        decrypt_at_rest("wrong-pass", blob)


def test_at_rest_is_randomised():
    """Encrypting the same data twice yields different blobs (fresh salt/nonce)."""
    a = encrypt_at_rest("pass", b"same data")
    b = encrypt_at_rest("pass", b"same data")
    assert a != b
    assert decrypt_at_rest("pass", a) == decrypt_at_rest("pass", b) == b"same data"


def test_at_rest_rejects_empty_passphrase():
    with pytest.raises(ValueError):
        encrypt_at_rest("", b"data")


def test_at_rest_rejects_malformed_blob():
    with pytest.raises(ValueError):
        decrypt_at_rest("pass", b"not a vault blob")


def test_wipe_bytes_zeroes_bytearray():
    buf = bytearray(b"secret")
    assert wipe_bytes(buf) is None
    assert bytes(buf) == b"\x00" * 6


def test_wipe_bytes_ignores_immutable():
    # Should not raise on immutable bytes.
    assert wipe_bytes(b"secret") is None


# ── Ed25519 identity + handshake signatures ──────────────────────────

def test_identity_keypair_generation():
    priv, pub = generate_identity_keypair()
    assert len(priv) == 32
    assert len(pub) == 32
    priv2, pub2 = generate_identity_keypair()
    assert priv != priv2 and pub != pub2


def test_identity_public_from_private_is_deterministic():
    priv, pub = generate_identity_keypair()
    assert identity_public_from_private(priv) == pub


def test_identity_public_from_private_rejects_bad_length():
    with pytest.raises(ValueError):
        identity_public_from_private(b"too short")


def test_sign_and_verify_handshake_roundtrip():
    id_priv, id_pub = generate_identity_keypair()
    _, ephemeral_pub = generate_keypair()
    sig = sign_handshake(id_priv, ephemeral_pub)
    assert len(sig) == 64
    assert verify_handshake(id_pub, ephemeral_pub, sig) is True


def test_verify_handshake_rejects_tampered_ephemeral():
    id_priv, id_pub = generate_identity_keypair()
    _, ephemeral_pub = generate_keypair()
    sig = sign_handshake(id_priv, ephemeral_pub)
    _, other_ephemeral = generate_keypair()
    assert verify_handshake(id_pub, other_ephemeral, sig) is False


def test_verify_handshake_rejects_wrong_identity():
    id_priv, _ = generate_identity_keypair()
    _, other_pub = generate_identity_keypair()
    _, ephemeral_pub = generate_keypair()
    sig = sign_handshake(id_priv, ephemeral_pub)
    assert verify_handshake(other_pub, ephemeral_pub, sig) is False


def test_verify_handshake_rejects_bad_lengths():
    _, id_pub = generate_identity_keypair()
    _, ephemeral_pub = generate_keypair()
    assert verify_handshake(b"short", ephemeral_pub, b"x" * 64) is False
    assert verify_handshake(id_pub, ephemeral_pub, b"short sig") is False


def test_sign_and_verify_handshake_v2_nonce_roundtrip():
    id_priv, id_pub = generate_identity_keypair()
    _, ephemeral_pub = generate_keypair()
    nonce = make_handshake_nonce()
    sig = sign_handshake(id_priv, ephemeral_pub, nonce)
    assert verify_handshake(id_pub, ephemeral_pub, sig, nonce) is True


def test_v2_signature_rejects_tampered_nonce():
    id_priv, id_pub = generate_identity_keypair()
    _, ephemeral_pub = generate_keypair()
    nonce = make_handshake_nonce()
    sig = sign_handshake(id_priv, ephemeral_pub, nonce)
    other_nonce = make_handshake_nonce()
    assert verify_handshake(id_pub, ephemeral_pub, sig, other_nonce) is False


def test_v2_signature_rejects_stale_nonce():
    import struct as _struct
    id_priv, id_pub = generate_identity_keypair()
    _, ephemeral_pub = generate_keypair()
    # Forge a nonce with a timestamp far in the past
    stale = _struct.pack(">Q", 1) + b"\x00" * 8
    sig = sign_handshake(id_priv, ephemeral_pub, stale)
    assert verify_handshake(id_pub, ephemeral_pub, sig, stale) is False


def test_v1_and_v2_signatures_are_not_interchangeable():
    id_priv, id_pub = generate_identity_keypair()
    _, ephemeral_pub = generate_keypair()
    nonce = make_handshake_nonce()
    # A v1 signature must not validate when a nonce is supplied (v2 path).
    v1_sig = sign_handshake(id_priv, ephemeral_pub)
    assert verify_handshake(id_pub, ephemeral_pub, v1_sig, nonce) is False
    # A v2 signature must not validate on the v1 (no-nonce) path.
    v2_sig = sign_handshake(id_priv, ephemeral_pub, nonce)
    assert verify_handshake(id_pub, ephemeral_pub, v2_sig) is False


def test_handshake_nonce_freshness():
    import struct as _struct
    assert handshake_nonce_is_fresh(make_handshake_nonce()) is True
    assert handshake_nonce_is_fresh(_struct.pack(">Q", 1) + b"\x00" * 8) is False
    assert handshake_nonce_is_fresh(b"\x00" * 4) is False


def test_fingerprint_is_deterministic_and_hex():
    _, pub = generate_identity_keypair()
    fp = fingerprint(pub)
    assert fp == fingerprint(pub)
    parts = fp.split(":")
    assert len(parts) == 8
    assert all(len(p) == 2 for p in parts)


# ── Traffic-analysis padding ─────────────────────────────────────────

def test_pad_frame_quantises_to_block():
    block = 256
    for size in (1, 100, 255, 256, 257, 500):
        padded = pad_frame(b"\x01" * size, block)
        assert len(padded) % block == 0
        assert len(padded) >= size + 2  # length prefix + data


def test_pad_unpad_roundtrip():
    for size in (0, 1, 50, 255, 256, 1000):
        data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
        data = data[:size]
        assert unpad_frame(pad_frame(data, 256)) == data


def test_pad_frame_hides_size_differences():
    """Two very differently sized frames should pad to the same length when
    they fall in the same block."""
    a = pad_frame(b"\x00" * 10, 256)
    b = pad_frame(b"\x00" * 200, 256)
    assert len(a) == len(b) == 256


def test_pad_frame_rejects_bad_block():
    with pytest.raises(ValueError):
        pad_frame(b"data", 0)


def test_pad_frame_rejects_oversized():
    with pytest.raises(ValueError):
        pad_frame(b"\x00" * 70000, 256)


def test_unpad_frame_rejects_short_and_inconsistent():
    with pytest.raises(ValueError):
        unpad_frame(b"\x00")  # too short
    with pytest.raises(ValueError):
        unpad_frame(b"\xff\xff\x01")  # prefix claims 65535 bytes
