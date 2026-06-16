import pytest
import socket
import threading
import io
from torcall.network.protocol import (
    MessageType,
    Packet,
    MAX_SEQUENCE,
    read_packet_sync,
    encode_handshake,
    decode_handshake,
)

def test_packet_encode_decode():
    """Verify that a Packet can be encoded to bytes and decoded back correctly."""
    payload = b"test payload"
    pkt = Packet(MessageType.CALL_REQUEST, 42, payload)
    
    encoded = pkt.encode()
    assert len(encoded) == 7 + len(payload) # 7 bytes header + payload
    
    decoded = Packet.from_bytes(encoded)
    assert decoded.msg_type == MessageType.CALL_REQUEST
    assert decoded.sequence == 42
    assert decoded.payload == payload

def test_packet_empty_payload():
    """Verify that a Packet with an empty payload encodes and decodes correctly."""
    pkt = Packet(MessageType.CALL_REJECT, 10)
    encoded = pkt.encode()
    assert len(encoded) == 7
    
    decoded = Packet.from_bytes(encoded)
    assert decoded.msg_type == MessageType.CALL_REJECT
    assert decoded.sequence == 10
    assert decoded.payload == b""

def test_decode_invalid_header():
    """Verify that decoding fails on incomplete headers."""
    with pytest.raises(ValueError, match="Header requires"):
        Packet.decode_header(b"\x01\x02")


def test_max_sequence_fits_header_but_overflow_does_not():
    """MAX_SEQUENCE is the largest seq the 32-bit header can hold; +1 fails."""
    pkt = Packet(MessageType.AUDIO_DATA, MAX_SEQUENCE, b"x")
    decoded = Packet.from_bytes(pkt.encode())
    assert decoded.sequence == MAX_SEQUENCE
    with pytest.raises(Exception):
        Packet(MessageType.AUDIO_DATA, MAX_SEQUENCE + 1, b"x").encode()

def test_decode_incomplete_payload():
    """Verify that decoding fails if the payload length is shorter than specified in header."""
    pkt = Packet(MessageType.AUDIO_DATA, 1, b"hello")
    encoded = pkt.encode()
    
    # Truncate the payload by 1 byte
    truncated = encoded[:-1]
    
    with pytest.raises(ValueError, match="Incomplete payload"):
        Packet.from_bytes(truncated)

def test_read_packet_sync():
    """Test read_packet_sync using a pair of connected sockets."""
    # Create two connected socket objects
    s1, s2 = socket.socketpair()
    s1.setblocking(True)
    s2.setblocking(True)
    
    pkt_to_send = Packet(MessageType.PING, 99, b"pingpayload")
    
    def run_client():
        s1.sendall(pkt_to_send.encode())
        s1.close()
        
    t = threading.Thread(target=run_client)
    t.start()
    
    try:
        received_pkt = read_packet_sync(s2)
        assert received_pkt is not None
        assert received_pkt.msg_type == MessageType.PING
        assert received_pkt.sequence == 99
        assert received_pkt.payload == b"pingpayload"
        
        # Next read should return None (EOF)
        eof_pkt = read_packet_sync(s2)
        assert eof_pkt is None
    finally:
        s2.close()
        t.join()


# ── Handshake payload encoding ────────────────────────────────────────

def test_encode_decode_handshake_full():
    ephemeral = b"\x01" * 32
    identity = b"\x02" * 32
    signature = b"\x03" * 64
    payload = encode_handshake(ephemeral, identity, signature)
    assert len(payload) == 128
    eph, ident, sig, nonce = decode_handshake(payload)
    assert eph == ephemeral
    assert ident == identity
    assert sig == signature
    assert nonce is None


def test_encode_decode_handshake_v2_with_nonce():
    ephemeral = b"\x01" * 32
    identity = b"\x02" * 32
    signature = b"\x03" * 64
    nonce = b"\x04" * 16
    payload = encode_handshake(ephemeral, identity, signature, nonce)
    assert len(payload) == 144
    eph, ident, sig, dec_nonce = decode_handshake(payload)
    assert eph == ephemeral
    assert ident == identity
    assert sig == signature
    assert dec_nonce == nonce


def test_encode_handshake_rejects_bad_nonce():
    with pytest.raises(ValueError):
        encode_handshake(b"\x01" * 32, b"\x02" * 32, b"\x03" * 64, b"shortnonce")


def test_encode_decode_handshake_legacy():
    ephemeral = b"\x07" * 32
    payload = encode_handshake(ephemeral)
    assert payload == ephemeral
    eph, ident, sig, nonce = decode_handshake(payload)
    assert eph == ephemeral
    assert ident is None
    assert sig is None
    assert nonce is None


def test_encode_handshake_rejects_bad_lengths():
    with pytest.raises(ValueError):
        encode_handshake(b"short")
    with pytest.raises(ValueError):
        encode_handshake(b"\x01" * 32, b"bad id", b"\x03" * 64)
    with pytest.raises(ValueError):
        encode_handshake(b"\x01" * 32, b"\x02" * 32, b"short sig")


def test_decode_handshake_rejects_unknown_length():
    with pytest.raises(ValueError):
        decode_handshake(b"\x00" * 50)
