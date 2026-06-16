"""
TorCall binary protocol.

Packet layout (7-byte header + variable payload)::

    ┌──────────┬──────────┬──────────┬──────────────┐
    │ Type 1B  │ Seq  4B  │ Len  2B  │ Payload …    │
    └──────────┴──────────┴──────────┴──────────────┘

All multi-byte integers are big-endian.
"""

from __future__ import annotations

import asyncio
import struct
from enum import IntEnum
from typing import Optional


class MessageType(IntEnum):
    """Protocol message types."""
    CALL_REQUEST = 0x01   # Payload: handshake blob (see encode_handshake)
    CALL_ACCEPT  = 0x02   # Payload: handshake blob (see encode_handshake)
    CALL_REJECT  = 0x03   # Payload: empty
    AUDIO_DATA   = 0x10   # Payload: nonce (12 B) + AES-GCM ciphertext
    CALL_END     = 0x20   # Payload: empty
    CALL_END_ACK = 0x21   # Payload: empty
    PING         = 0x30   # Payload: empty
    PONG         = 0x31   # Payload: empty


# ── Handshake payload ────────────────────────────────────────────────
#
# A handshake payload carries the ephemeral X25519 public key and,
# optionally, the sender's long-term Ed25519 identity plus a signature
# over the ephemeral key.  Three wire forms are accepted for backward
# compatibility:
#
#   * 32 bytes              → legacy: X25519 key only, no identity.
#   * 128 bytes             → v1: X25519(32) + Ed25519 id(32) + sig(64).
#   * 144 bytes             → v2: X25519(32) + Ed25519 id(32) + sig(64)
#                                  + freshness nonce(16).
#
_X25519_LEN = 32
_ED25519_LEN = 32
_SIGNATURE_LEN = 64
_NONCE_LEN = 16
_HANDSHAKE_FULL_LEN = _X25519_LEN + _ED25519_LEN + _SIGNATURE_LEN  # 128
_HANDSHAKE_V2_LEN = _HANDSHAKE_FULL_LEN + _NONCE_LEN  # 144


def encode_handshake(
    ephemeral_public: bytes,
    identity_public: Optional[bytes] = None,
    signature: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> bytes:
    """Build a CALL_REQUEST / CALL_ACCEPT payload.

    When *identity_public* and *signature* are provided the authenticated
    form is produced; appending *nonce* yields the freshness-bound v2
    (144-byte) form, otherwise the v1 (128-byte) form.  With neither
    identity nor signature, just the 32-byte ephemeral key (legacy form)
    is returned.
    """
    if len(ephemeral_public) != _X25519_LEN:
        raise ValueError(f"Ephemeral key must be {_X25519_LEN} bytes")
    if identity_public is None or signature is None:
        return ephemeral_public
    if len(identity_public) != _ED25519_LEN:
        raise ValueError(f"Identity key must be {_ED25519_LEN} bytes")
    if len(signature) != _SIGNATURE_LEN:
        raise ValueError(f"Signature must be {_SIGNATURE_LEN} bytes")
    base = ephemeral_public + identity_public + signature
    if nonce is None:
        return base
    if len(nonce) != _NONCE_LEN:
        raise ValueError(f"Nonce must be {_NONCE_LEN} bytes")
    return base + nonce


def decode_handshake(payload: bytes) -> tuple[bytes, Optional[bytes], Optional[bytes], Optional[bytes]]:
    """Parse a handshake payload.

    Returns ``(ephemeral_public, identity_public, signature, nonce)``
    where trailing fields are ``None`` for shorter forms (a legacy
    32-byte payload yields identity/signature/nonce = None; a v1 128-byte
    payload yields nonce = None).

    Raises:
        ValueError: if the payload length is not a recognised form.
    """
    if len(payload) == _X25519_LEN:
        return payload, None, None, None
    if len(payload) == _HANDSHAKE_FULL_LEN:
        ephemeral = payload[:_X25519_LEN]
        identity = payload[_X25519_LEN : _X25519_LEN + _ED25519_LEN]
        signature = payload[_X25519_LEN + _ED25519_LEN :]
        return ephemeral, identity, signature, None
    if len(payload) == _HANDSHAKE_V2_LEN:
        ephemeral = payload[:_X25519_LEN]
        identity = payload[_X25519_LEN : _X25519_LEN + _ED25519_LEN]
        signature = payload[_X25519_LEN + _ED25519_LEN : _HANDSHAKE_FULL_LEN]
        nonce = payload[_HANDSHAKE_FULL_LEN:]
        return ephemeral, identity, signature, nonce
    raise ValueError(f"Invalid handshake payload length: {len(payload)}")


# ── Header encoding ──────────────────────────────────────────────────
HEADER_FORMAT = ">BIH"  # type(1) + seq(4) + length(2)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 7 bytes

# The sequence field is an unsigned 32-bit integer, so it can hold values
# up to 2**32 - 1.  Senders must never let an audio counter reach this
# value: wrapping would both break struct packing and (far worse) reuse an
# AES-GCM nonce, which is catastrophic.  Callers should end/rekey the call
# before crossing this threshold.  At ~50 frames/s this is ~2.7 years.
MAX_SEQUENCE = 2 ** 32 - 1


class Packet:
    """A single protocol packet."""

    __slots__ = ("msg_type", "sequence", "payload")

    def __init__(self, msg_type: MessageType, sequence: int, payload: bytes = b""):
        self.msg_type = msg_type
        self.sequence = sequence
        self.payload = payload

    # ── Serialisation ────────────────────────────────────────────────

    def encode(self) -> bytes:
        """Serialise the packet to bytes (header + payload)."""
        header = struct.pack(HEADER_FORMAT, int(self.msg_type), self.sequence, len(self.payload))
        return header + self.payload

    # ── Deserialisation ──────────────────────────────────────────────

    @classmethod
    def decode_header(cls, data: bytes) -> tuple[MessageType, int, int]:
        """Decode only the header.  Returns (msg_type, sequence, payload_length)."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Header requires {HEADER_SIZE} bytes, got {len(data)}")
        raw_type, sequence, length = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        return MessageType(raw_type), sequence, length

    @classmethod
    def from_bytes(cls, data: bytes) -> "Packet":
        """Build a Packet from a complete byte buffer (header + payload)."""
        msg_type, sequence, length = cls.decode_header(data)
        payload = data[HEADER_SIZE : HEADER_SIZE + length]
        if len(payload) < length:
            raise ValueError(f"Incomplete payload: expected {length} bytes, got {len(payload)}")
        return cls(msg_type, sequence, payload)

    # ── Helpers ──────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return f"Packet({self.msg_type.name}, seq={self.sequence}, payload={len(self.payload)}B)"


# ── Stream reader helper ─────────────────────────────────────────────

async def read_packet(reader) -> Optional[Packet]:
    """
    Read exactly one packet from an asyncio StreamReader.

    Returns ``None`` on EOF.
    """
    try:
        header_data = await reader.readexactly(HEADER_SIZE)
    except asyncio.IncompleteReadError:
        return None  # EOF before a full header arrived
    msg_type, sequence, length = Packet.decode_header(header_data)

    payload = b""
    if length > 0:
        try:
            payload = await reader.readexactly(length)
        except asyncio.IncompleteReadError:
            return None  # connection closed mid-payload

    return Packet(msg_type, sequence, payload)


def read_packet_sync(sock) -> Optional[Packet]:
    """
    Read exactly one packet from a blocking socket.

    Returns ``None`` on EOF / connection closed.
    """
    header_data = _recv_exactly(sock, HEADER_SIZE)
    if header_data is None:
        return None
    msg_type, sequence, length = Packet.decode_header(header_data)

    payload = b""
    if length > 0:
        payload = _recv_exactly(sock, length)
        if payload is None:
            return None

    return Packet(msg_type, sequence, payload)


def _recv_exactly(sock, n: int) -> Optional[bytes]:
    """Receive exactly *n* bytes from a socket, or return None on EOF."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)
