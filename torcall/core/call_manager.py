"""
TorCall call manager — the orchestrator.

Coordinates the Tor manager, audio engine, network server/client,
and cryptographic layer to drive the complete lifecycle of a voice
call.

State machine::

    Idle ──▶ Dialing ──▶ Connecting ──▶ InCall ──▶ Idle
    Idle ──▶ Ringing ──▶ Connecting ──▶ InCall ──▶ Idle
"""

from __future__ import annotations

import queue
import socket
import threading
import time
from enum import Enum, auto
from typing import Optional

from PySide6.QtCore import QObject, QTimer, Signal

from torcall.core.crypto import (
    generate_keypair,
    derive_session_keys,
    compute_sas,
    sign_handshake,
    verify_handshake,
    make_handshake_nonce,
    fingerprint,
    encrypt,
    decrypt,
    make_nonce,
    pad_frame,
    unpad_frame,
    wipe_bytes,
)
from torcall.core.identity import Identity, ContactStore
from torcall.core.audio_engine import AudioEngine
from torcall.network.protocol import (
    Packet,
    MessageType,
    MAX_SEQUENCE,
    read_packet_sync,
    encode_handshake,
    decode_handshake,
)
from torcall.network.server import CallServer
from torcall.network.client import CallClient
from torcall.utils.config import (
    HIDDEN_SERVICE_LOCAL_PORT,
    HIDDEN_SERVICE_REMOTE_PORT,
    AES_NONCE_SIZE,
    PING_INTERVAL_S,
    PING_TIMEOUT_S,
    TRAFFIC_PAD_BLOCK,
    CONSTANT_RATE_SEND,
    REQUIRE_SAS_CONFIRMATION,
    RECONNECT_MAX_ATTEMPTS,
    RECONNECT_DELAY_MS,
    SAMPLE_RATE,
    FRAME_SIZE,
)
from torcall.utils.logger import log


# ── Call states ──────────────────────────────────────────────────────

class CallState(Enum):
    IDLE = auto()
    DIALING = auto()
    RINGING = auto()
    CONNECTING = auto()
    IN_CALL = auto()


# ── Call manager ─────────────────────────────────────────────────────

class CallManager(QObject):
    """
    Orchestrates an end-to-end encrypted voice call.

    Signals
    -------
    state_changed(str)
        Human-readable state description for the UI.
    call_started(str)
        Emitted when a call is fully established.  Arg = peer address.
    call_ended()
        Emitted when the call ends (any reason).
    incoming_call(str)
        Emitted when a remote peer is calling us.  Arg = peer address.
    error(str)
        Emitted on any failure.
    sas_ready(str)
        Emitted once per call with the Short Authentication String the
        two peers should read aloud to detect an active MITM.
    peer_identity(dict)
        Emitted once per call with the peer's identity status.  Keys:
        ``status`` ("new"|"match"|"mismatch"|"unsigned"),
        ``fingerprint`` (str), ``address`` (str).
    """

    state_changed = Signal(str)
    call_started = Signal(str)
    call_ended = Signal()
    incoming_call = Signal(str)
    error = Signal(str)
    sas_ready = Signal(str)
    peer_identity = Signal(dict)
    # Emitted when audio is being held pending the user's SAS confirmation
    # (only when TORCALL_REQUIRE_SAS gating is on).  Arg = True while held.
    sas_confirmation_required = Signal(bool)

    def __init__(
        self,
        audio_engine: AudioEngine,
        server: CallServer,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)

        self._audio = audio_engine
        self._server = server
        self._client: Optional[CallClient] = None

        # Long-term identity + pinned contacts (TOFU)
        self._identity = Identity()
        self._contacts = ContactStore()
        self._contacts.load()

        # Current call state
        self._state = CallState.IDLE
        self._peer_address: Optional[str] = None
        # Our own .onion address, advertised inside the handshake so the
        # callee can pin us under it (its socket only sees loopback).
        self._local_address: Optional[str] = None
        self._call_socket: Optional[socket.socket] = None
        self._socket_lock = threading.Lock()  # serialises sendall() across threads

        # Crypto — ephemeral per call
        self._my_private: Optional[bytes] = None
        self._my_public: Optional[bytes] = None
        self._send_key: Optional[bytes] = None
        self._recv_key: Optional[bytes] = None
        self._send_seq = 0
        self._last_recv_seq = -1  # highest audio sequence accepted (anti-replay)
        self._ping_seq = 0  # independent counter for PING (not used as a nonce)

        # Network threads
        self._recv_thread: Optional[threading.Thread] = None
        self._recv_running = False

        # Send pipeline (offloads encode/encrypt/sendall from the UI thread)
        self._send_thread: Optional[threading.Thread] = None
        self._send_running = False
        self._send_queue: "queue.Queue[Optional[bytes]]" = queue.Queue(maxsize=50)

        # Keep-alive
        self._ping_timer = QTimer(self)
        self._ping_timer.setInterval(PING_INTERVAL_S * 1000)
        self._ping_timer.timeout.connect(self._send_ping)
        self._last_rx_time = 0.0  # monotonic timestamp of last received packet

        # Incoming call deferred data
        self._pending_incoming: Optional[dict] = None

        # SAS / peer-identity are computed during the handshake but must be
        # surfaced *after* the in-call widget is shown, otherwise the widget's
        # start_call() -> clear_sas() reset wipes them immediately.
        self._pending_sas: Optional[str] = None
        self._pending_peer_identity: Optional[dict] = None

        # When SAS gating is enabled (TORCALL_REQUIRE_SAS), real microphone
        # audio is neither transmitted nor played until the user confirms the
        # SAS words match — a verbal defence against an active MITM.  With
        # gating off this stays True so audio always flows.
        self._sas_confirmed = not REQUIRE_SAS_CONFIRMATION

        # Auto-reconnect bookkeeping.  Only the caller can re-dial (it knows
        # the peer's .onion address); _user_ended distinguishes a deliberate
        # hang-up from a dropped circuit so we don't reconnect after the user
        # ends the call themselves.
        self._is_caller = False
        self._user_ended = False
        self._reconnect_attempts = 0
        self._reconnecting = False

        # Wire server signal
        self._server.incoming_call.connect(self._on_incoming_call)

        # Wire audio capture → send
        self._audio.audio_captured.connect(self._on_audio_captured)

    # ── Address book ─────────────────────────────────────────────────

    def list_contacts(self) -> list[dict]:
        """Return the known contacts (one entry per identity) for the UI."""
        return self._contacts.all_contacts()

    def rename_contact(self, address: str, name: str) -> None:
        """Assign a human-readable name to the contact at *address*."""
        self._contacts.set_name(address, name)

    def remove_contact(self, address: str) -> int:
        """Remove the contact at *address* (and any sibling addresses sharing
        the same identity) from the address book.  Returns how many address
        entries were removed."""
        return self._contacts.remove(address)

    # ── State helpers ────────────────────────────────────────────────

    def _set_state(self, state: CallState, status_text: str = "") -> None:
        self._state = state
        text = status_text or state.name.replace("_", " ").title()
        self.state_changed.emit(text)
        log.info("CallManager state → %s", text)

    @property
    def state(self) -> CallState:
        return self._state

    def _send_packet(self, pkt: Packet) -> bool:
        """Send a packet on the call socket, serialised across threads.

        Multiple threads (send loop, recv loop, ping timer) may transmit
        concurrently; without a lock their byte streams could interleave
        and corrupt the framing.  Returns True on success.
        """
        sock = self._call_socket
        if sock is None:
            return False
        try:
            with self._socket_lock:
                sock.sendall(pkt.encode())
            return True
        except OSError:
            return False

    # ── Identity handshake helpers ───────────────────────────────────

    def set_local_address(self, address: Optional[str]) -> None:
        """Record our own ``.onion`` address so it can be advertised inside
        the handshake.

        The callee's listening socket only ever sees a loopback peer
        address (Tor forwards the hidden-service port to ``127.0.0.1``), so
        the *caller* must tell the callee which ``.onion`` it can be reached
        and pinned under.  We advertise it on both legs of the handshake.
        """
        self._local_address = address or None

    def _build_handshake(self) -> bytes:
        """Build a signed handshake payload binding our ephemeral key to
        our long-term identity, with a per-call freshness nonce so the
        signature can't be replayed later to impersonate us.

        When our own ``.onion`` address is known it is advertised inside the
        payload and bound into the signature (v3 form), so the peer can pin
        us under our real address rather than the loopback address its
        socket would otherwise see for an incoming call."""
        nonce = make_handshake_nonce()
        onion = self._local_address
        signature = sign_handshake(
            self._identity.private_key, self._my_public, nonce, onion
        )
        return encode_handshake(
            self._my_public,
            self._identity.public_key,
            signature,
            nonce,
            onion,
        )

    def _close_socket_quietly(self, sock) -> None:
        """Close a socket, swallowing errors."""
        try:
            sock.close()
        except OSError:
            pass

    def _verify_peer_identity(self, payload: bytes, address: str) -> Optional[bytes]:
        """Decode a peer handshake payload, verify its signature, and pin
        the identity (TOFU).

        *address* is the address we already associate with the peer — the
        ``.onion`` we dialled (caller side) or the loopback socket address
        (callee side).  When the handshake advertises the peer's own
        ``.onion`` (v3 form) that advertised address is preferred for
        pinning, because for an incoming call the socket address is always
        loopback and useless as a contact handle.

        Stashes the identity outcome in :attr:`_pending_peer_identity` (so it
        can be surfaced *after* the in-call widget is shown) and returns the
        peer's ephemeral X25519 public key, or ``None`` if the payload is
        malformed.
        """
        try:
            ephemeral, identity_pub, signature, nonce, advertised_addr = decode_handshake(payload)
        except ValueError:
            log.warning("Malformed handshake payload from %s", address)
            return None

        if identity_pub is None or signature is None:
            # Legacy peer without identity support
            self._pending_peer_identity = {
                "status": "unsigned",
                "fingerprint": "",
                "address": address,
            }
            return ephemeral

        if not verify_handshake(identity_pub, ephemeral, signature, nonce, advertised_addr):
            log.warning("Invalid handshake signature from %s", address)
            self._pending_peer_identity = {
                "status": "mismatch",
                "fingerprint": fingerprint(identity_pub),
                "address": address,
            }
            return ephemeral

        # Prefer the signed, peer-advertised .onion address for pinning.
        # The socket address is loopback for incoming calls and would
        # otherwise be saved as the contact's "address" (the 127.0.0.1 bug).
        pin_address = advertised_addr or address

        status = self._contacts.check(pin_address, identity_pub)
        self._pending_peer_identity = {
            "status": status,
            "fingerprint": fingerprint(identity_pub),
            "address": pin_address,
            "name": self._contacts.name_for_key(identity_pub.hex()),
        }
        return ephemeral

    # ══════════════════════════════════════════════════════════════════
    # OUTGOING CALL
    # ══════════════════════════════════════════════════════════════════

    def place_call(self, onion_address: str) -> None:
        """Initiate an outgoing call to *onion_address*."""
        if self._state != CallState.IDLE:
            self.error.emit("Already in a call")
            return

        # Fresh call: we are the caller, nothing has been torn down by the
        # user, and the reconnect budget is full.
        self._is_caller = True
        self._user_ended = False
        self._reconnect_attempts = 0
        self._reconnecting = False

        self._set_state(CallState.DIALING, "Dialing…")
        self._peer_address = onion_address
        self._dial(onion_address)

    def _dial(self, onion_address: str) -> None:
        """Open a client connection and send our signed handshake.

        Shared by :meth:`place_call` and the auto-reconnect path.
        """
        # Generate ephemeral key pair (private kept mutable so it can be wiped)
        priv, self._my_public = generate_keypair()
        self._my_private = bytearray(priv)

        # Create client and connect
        self._client = CallClient()
        self._client.connected.connect(self._on_outgoing_connected)
        self._client.rejected.connect(self._on_outgoing_rejected)
        self._client.connection_failed.connect(self._on_outgoing_failed)
        self._client.connection_timeout.connect(self._on_outgoing_timeout)

        # Send a signed handshake binding our ephemeral key to our identity
        handshake = self._build_handshake()
        port = HIDDEN_SERVICE_REMOTE_PORT
        self._client.connect_to(onion_address, port, handshake)

    def cancel_call(self) -> None:
        """Cancel an outgoing call in progress."""
        self._user_ended = True
        if self._client:
            self._client.cancel()
            self._client = None
        self._cleanup_call()
        self._set_state(CallState.IDLE, "Call cancelled")

    # ── Outgoing call callbacks ──────────────────────────────────────

    def _on_outgoing_connected(self, info: dict) -> None:
        """Remote peer accepted our call."""
        sock = info["socket"]
        peer_payload = info["peer_public_key"]

        # Verify the peer's signed handshake and pin their identity (TOFU)
        peer_public = self._verify_peer_identity(peer_payload, self._peer_address or "unknown")
        if peer_public is None:
            self._close_socket_quietly(sock)
            self._cleanup_call()
            self._set_state(CallState.IDLE, "Idle")
            self.error.emit("Peer sent a malformed handshake")
            return

        # Derive directional session keys (we are the caller).
        # Keep them as bytearray so we can zero them out on cleanup.
        send_key, recv_key = derive_session_keys(
            self._my_private, peer_public, is_caller=True
        )
        self._send_key = bytearray(send_key)
        self._recv_key = bytearray(recv_key)
        self._call_socket = sock
        self._send_seq = 0
        self._last_recv_seq = -1

        # Connection established — reset the reconnect budget for next time.
        self._reconnecting = False
        self._reconnect_attempts = 0

        # SAS for verbal MITM verification (same value on both peers).
        # Stashed and surfaced after the call widget is shown (see
        # _start_call_session) so the widget reset doesn't wipe it.
        self._pending_sas = compute_sas(self._my_public, peer_public)

        self._server.set_busy(True)
        self._start_call_session()

    def _on_outgoing_rejected(self) -> None:
        self._cleanup_call()
        self._set_state(CallState.IDLE, "Call rejected")

    def _on_outgoing_failed(self, msg: str) -> None:
        # If this failure happened mid-reconnect, keep retrying until the
        # budget is exhausted instead of giving up immediately.
        if self._reconnecting and not self._user_ended and self._is_caller \
                and self._peer_address and self._reconnect_attempts < RECONNECT_MAX_ATTEMPTS:
            self._attempt_reconnect()
            return
        was_reconnecting = self._reconnecting
        self._cleanup_call()
        self._set_state(CallState.IDLE, "Idle")
        self.error.emit(f"Connection failed: {msg}")
        # Only signal call_ended if a previously-established call dropped
        # (the in-call widget is showing); a failed initial dial never
        # showed it.
        if was_reconnecting:
            self.call_ended.emit()

    def _on_outgoing_timeout(self) -> None:
        if self._reconnecting and not self._user_ended and self._is_caller \
                and self._peer_address and self._reconnect_attempts < RECONNECT_MAX_ATTEMPTS:
            self._attempt_reconnect()
            return
        was_reconnecting = self._reconnecting
        self._cleanup_call()
        self._set_state(CallState.IDLE, "Idle")
        self.error.emit("Call timed out — no answer")
        if was_reconnecting:
            self.call_ended.emit()

    # ══════════════════════════════════════════════════════════════════
    # INCOMING CALL
    # ══════════════════════════════════════════════════════════════════

    def _on_incoming_call(self, info: dict) -> None:
        """Server received a CALL_REQUEST from a remote peer."""
        if self._state != CallState.IDLE:
            # Auto-reject (server already sends CALL_REJECT when busy,
            # but this is a safety net)
            try:
                reject = Packet(MessageType.CALL_REJECT, 0)
                info["socket"].sendall(reject.encode())
                info["socket"].close()
            except OSError:
                pass
            return

        self._pending_incoming = info
        self._peer_address = info.get("address", "unknown")
        self._set_state(CallState.RINGING, "Ringing…")
        self.incoming_call.emit(self._peer_address)

    def accept_call(self) -> None:
        """Accept the pending incoming call."""
        if self._state != CallState.RINGING or not self._pending_incoming:
            return

        # We are the callee: we have no address to call back, so we can't
        # auto-reconnect.  A deliberate hang-up hasn't happened yet.
        self._is_caller = False
        self._user_ended = False
        self._reconnect_attempts = 0
        self._reconnecting = False

        info = self._pending_incoming
        self._pending_incoming = None

        # Generate ephemeral key pair (private kept mutable so it can be wiped)
        priv, self._my_public = generate_keypair()
        self._my_private = bytearray(priv)

        sock = info["socket"]
        address = info.get("address", "unknown")

        # Verify the caller's signed handshake and pin their identity (TOFU)
        peer_public = self._verify_peer_identity(info["peer_public_key"], address)
        if peer_public is None:
            self._close_socket_quietly(sock)
            self._cleanup_call()
            self._set_state(CallState.IDLE, "Idle")
            self.error.emit("Peer sent a malformed handshake")
            return

        # Send CALL_ACCEPT with our signed handshake
        try:
            accept_pkt = Packet(MessageType.CALL_ACCEPT, 0, self._build_handshake())
            sock.sendall(accept_pkt.encode())
        except OSError as exc:
            self.error.emit(f"Failed to accept call: {exc}")
            self._cleanup_call()
            self._set_state(CallState.IDLE)
            return

        # Derive directional session keys (we are the callee).
        # Keep them as bytearray so we can zero them out on cleanup.
        send_key, recv_key = derive_session_keys(
            self._my_private, peer_public, is_caller=False
        )
        self._send_key = bytearray(send_key)
        self._recv_key = bytearray(recv_key)
        self._call_socket = sock
        self._send_seq = 0
        self._last_recv_seq = -1

        # SAS for verbal MITM verification (same value on both peers).
        # Stashed and surfaced after the call widget is shown (see
        # _start_call_session) so the widget reset doesn't wipe it.
        self._pending_sas = compute_sas(self._my_public, peer_public)

        self._server.set_busy(True)
        self._start_call_session()

    def reject_call(self) -> None:
        """Reject the pending incoming call."""
        if self._pending_incoming:
            try:
                reject = Packet(MessageType.CALL_REJECT, 0)
                self._pending_incoming["socket"].sendall(reject.encode())
                self._pending_incoming["socket"].close()
            except OSError:
                pass
            self._pending_incoming = None

        self._set_state(CallState.IDLE, "Idle")

    # ══════════════════════════════════════════════════════════════════
    # ACTIVE CALL SESSION
    # ══════════════════════════════════════════════════════════════════

    def _start_call_session(self) -> None:
        """Begin audio streaming and network I/O."""
        self._set_state(CallState.IN_CALL, "Connected")

        # Start audio
        self._audio.start()

        # Drain any stale frames left in the send queue from a previous call
        while not self._send_queue.empty():
            try:
                self._send_queue.get_nowait()
            except queue.Empty:
                break

        # Start the send pipeline (encode/encrypt/sendall off the UI thread)
        self._send_running = True
        self._send_thread = threading.Thread(
            target=self._send_loop, daemon=True, name="torcall-send"
        )
        self._send_thread.start()

        # Start receiving in a background thread
        self._last_rx_time = time.monotonic()
        self._recv_running = True
        self._recv_thread = threading.Thread(
            target=self._recv_loop, daemon=True, name="torcall-recv"
        )
        self._recv_thread.start()

        # Start keep-alive pings
        self._ping_timer.start()

        self.call_started.emit(self._peer_address or "unknown")

        # Now that the in-call widget is shown (and has reset itself), surface
        # the peer identity and SAS that were computed during the handshake.
        if self._pending_peer_identity is not None:
            self.peer_identity.emit(self._pending_peer_identity)
            self._pending_peer_identity = None
        if self._pending_sas is not None:
            self.sas_ready.emit(self._pending_sas)
            self._pending_sas = None

        # If SAS gating is on, audio is held until the user confirms; tell the
        # UI to surface a confirm prompt.  Otherwise audio already flows.
        self.sas_confirmation_required.emit(not self._sas_confirmed)

    def end_call(self) -> None:
        """End the current call (gracefully)."""
        if self._state not in (CallState.IN_CALL, CallState.CONNECTING):
            return

        # Deliberate hang-up: suppress any auto-reconnect.
        self._user_ended = True

        # Send CALL_END
        if self._call_socket:
            self._send_packet(Packet(MessageType.CALL_END, self._send_seq))

        self._cleanup_call()
        self._set_state(CallState.IDLE, "Idle")
        self.call_ended.emit()

    # ── Audio capture → encrypt → send ───────────────────────────────

    def _on_audio_captured(self, pcm_data: bytes) -> None:
        """Queue a captured audio frame for the send thread.

        Runs on the audio/GUI thread, so it must stay cheap: the heavy
        work (Opus encode + AES-GCM encrypt + blocking ``sendall``) is
        offloaded to :meth:`_send_loop` via a bounded queue.
        """
        if self._state != CallState.IN_CALL or not self._send_key:
            return
        # Hold the microphone until the SAS has been confirmed (MITM guard).
        if not self._sas_confirmed:
            return
        try:
            self._send_queue.put_nowait(pcm_data)
        except queue.Full:
            # Drop the oldest frame to keep latency bounded under congestion.
            try:
                self._send_queue.get_nowait()
                self._send_queue.put_nowait(pcm_data)
            except (queue.Empty, queue.Full):
                pass

    # ── Send loop (background thread) ─────────────────────────────────

    def _transmit_frame(self, opus_data: bytes) -> bool:
        """Pad, encrypt, and send a single Opus frame.

        Padding the plaintext to a fixed block size before encryption
        hides the variable-bitrate size signal that would otherwise reveal
        speech vs. silence.  Returns True on success.
        """
        key = self._send_key
        sock = self._call_socket
        if key is None or sock is None:
            return False
        # Guard against sequence-number / nonce exhaustion.  The 32-bit
        # header field wraps at 2**32 and reusing an AES-GCM nonce would be
        # catastrophic, so refuse to transmit past the limit and end the
        # call instead (a fresh call rekeys with new ephemeral keys).
        if self._send_seq >= MAX_SEQUENCE:
            log.error("Audio sequence number exhausted — ending call to avoid nonce reuse")
            self._handle_peer_disconnect()
            return False
        padded = pad_frame(opus_data, TRAFFIC_PAD_BLOCK)
        nonce = make_nonce(self._send_seq)
        encrypted = encrypt(key, padded, nonce)
        pkt = Packet(MessageType.AUDIO_DATA, self._send_seq, nonce + encrypted)
        if not self._send_packet(pkt):
            return False
        self._send_seq += 1
        return True

    def _send_loop(self) -> None:
        """Encode, encrypt, and transmit queued audio frames off the UI thread.

        In constant-rate mode the loop ticks once per audio frame and
        transmits a *silence* frame whenever the capture queue is empty, so
        an observer watching the encrypted stream cannot tell when the user
        is actually speaking.  Otherwise it sends only captured frames.
        """
        log.info("Send loop started (constant_rate=%s)", CONSTANT_RATE_SEND)
        frame_interval = FRAME_SIZE / SAMPLE_RATE  # seconds per 20 ms frame
        # A frame of digital silence (matches captured PCM frame size).
        silence_pcm = b"\x00" * (FRAME_SIZE * 2)  # int16 mono

        while self._send_running:
            if self._send_key is None or self._call_socket is None:
                break

            if CONSTANT_RATE_SEND:
                next_tick = time.monotonic() + frame_interval
                try:
                    pcm_data = self._send_queue.get(timeout=frame_interval)
                except queue.Empty:
                    pcm_data = silence_pcm  # cover the gap with silence
                if pcm_data is None:  # sentinel → shutdown
                    break
            else:
                try:
                    pcm_data = self._send_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                if pcm_data is None:  # sentinel → shutdown
                    break

            try:
                opus_data = self._audio.encode(pcm_data)
                if not self._transmit_frame(opus_data):
                    log.warning("Send failed — ending call")
                    self._handle_peer_disconnect()
                    break
            except Exception:
                log.exception("Error sending audio")

            if CONSTANT_RATE_SEND:
                # Sleep off whatever time is left to keep a steady cadence.
                slack = next_tick - time.monotonic()
                if slack > 0:
                    time.sleep(slack)

        log.info("Send loop ended")

    # ── Receive loop (background thread) ─────────────────────────────

    def _recv_loop(self) -> None:
        """Read packets from the peer and dispatch them."""
        log.info("Receive loop started")
        while self._recv_running and self._call_socket:
            try:
                pkt = read_packet_sync(self._call_socket)
                if pkt is None:
                    log.info("Peer closed connection")
                    self._handle_peer_disconnect()
                    break

                self._dispatch_packet(pkt)

            except OSError:
                if self._recv_running:
                    log.warning("Receive error — peer disconnected")
                    self._handle_peer_disconnect()
                break
            except Exception:
                log.exception("Error in receive loop")
                break

        log.info("Receive loop ended")

    def _dispatch_packet(self, pkt: Packet) -> None:
        """Handle a received packet by type."""
        # Any valid packet counts as liveness for the keep-alive watchdog.
        self._last_rx_time = time.monotonic()

        if pkt.msg_type == MessageType.AUDIO_DATA:
            self._handle_audio_packet(pkt)
        elif pkt.msg_type == MessageType.CALL_END:
            log.info("Peer ended the call")
            # Send ACK
            self._send_packet(Packet(MessageType.CALL_END_ACK, pkt.sequence))
            # Peer hung up deliberately — don't try to reconnect.
            self._user_ended = True
            self._handle_peer_disconnect()
        elif pkt.msg_type == MessageType.CALL_END_ACK:
            pass  # We're already tearing down
        elif pkt.msg_type == MessageType.PING:
            self._send_packet(Packet(MessageType.PONG, pkt.sequence))
        elif pkt.msg_type == MessageType.PONG:
            pass  # keep-alive acknowledged
        else:
            log.debug("Unexpected packet type: %s", pkt.msg_type.name)

    def _handle_audio_packet(self, pkt: Packet) -> None:
        """Decrypt and play an incoming audio packet."""
        if not self._recv_key:
            return

        # Anti-replay: the sender's counter is strictly increasing, so a
        # sequence we have already accepted (or one far in the past) is a
        # replay or a stale/reordered frame — drop it.
        if pkt.sequence <= self._last_recv_seq:
            log.debug("Dropping replayed/out-of-order audio seq=%d (last=%d)",
                      pkt.sequence, self._last_recv_seq)
            return

        try:
            payload = pkt.payload
            nonce = payload[:AES_NONCE_SIZE]
            ciphertext = payload[AES_NONCE_SIZE:]

            padded = decrypt(self._recv_key, ciphertext, nonce)
            opus_data = unpad_frame(padded)
            pcm_data = self._audio.decode(opus_data)
            # Decrypt (to keep the anti-replay counter advancing) but withhold
            # playback until the user has confirmed the SAS (MITM guard).
            if self._sas_confirmed:
                self._audio.play(pcm_data)

            # Only advance after successful authentication, so a forged
            # sequence number cannot poison the anti-replay window.
            self._last_recv_seq = pkt.sequence

        except Exception:
            log.debug("Failed to decrypt/decode audio packet seq=%d", pkt.sequence)

    # ── Keep-alive ───────────────────────────────────────────────────

    def _send_ping(self) -> None:
        """Send a PING and drop the call if the peer has gone silent."""
        if not self._call_socket or self._state != CallState.IN_CALL:
            return

        # Liveness watchdog: if nothing has arrived within PING_TIMEOUT_S,
        # treat the peer as dead even if sendall() still appears to work.
        if time.monotonic() - self._last_rx_time > PING_TIMEOUT_S:
            log.warning("No traffic from peer for %ds — assuming dead", PING_TIMEOUT_S)
            self._handle_peer_disconnect()
            return

        if not self._send_packet(Packet(MessageType.PING, self._ping_seq)):
            self._handle_peer_disconnect()
            return
        self._ping_seq += 1

    # ── Peer disconnect handling ─────────────────────────────────────

    def _handle_peer_disconnect(self) -> None:
        """Called when the peer disconnects unexpectedly."""
        # Use QTimer to ensure we're on the main thread
        QTimer.singleShot(0, self._peer_disconnect_main_thread)

    def _peer_disconnect_main_thread(self) -> None:
        if self._state == CallState.IDLE:
            return

        # If the drop was unexpected (not a deliberate hang-up by either
        # side) and we are the caller with attempts left, try to re-dial the
        # same .onion — the most common cause is a dead Tor circuit while
        # both parties are still online.
        if (
            not self._user_ended
            and self._is_caller
            and self._peer_address
            and self._reconnect_attempts < RECONNECT_MAX_ATTEMPTS
        ):
            self._attempt_reconnect()
            return

        self._cleanup_call()
        self._set_state(CallState.IDLE, "Call ended")
        self.call_ended.emit()

    def _attempt_reconnect(self) -> None:
        """Tear down the dropped connection and schedule a re-dial."""
        self._reconnect_attempts += 1
        self._reconnecting = True
        target = self._peer_address
        attempt = self._reconnect_attempts
        log.warning(
            "Connection lost — reconnecting to %s (attempt %d/%d)",
            (target or "")[:16], attempt, RECONNECT_MAX_ATTEMPTS,
        )

        # Release the dead socket/threads/keys but keep call-level state
        # (_peer_address, _is_caller, reconnect counters) intact.
        self._teardown_connection()
        self._set_state(
            CallState.DIALING,
            f"Reconnecting… ({attempt}/{RECONNECT_MAX_ATTEMPTS})",
        )

        # Brief pause before re-dialing to let Tor build a fresh circuit.
        QTimer.singleShot(RECONNECT_DELAY_MS, self._reconnect_now)

    def _reconnect_now(self) -> None:
        """Perform the actual re-dial (must run on the main thread)."""
        if self._user_ended or not self._peer_address:
            return
        self._dial(self._peer_address)

    # ── Cleanup ──────────────────────────────────────────────────────

    def _teardown_connection(self) -> None:
        """Release per-connection resources (socket, threads, audio, keys).

        Unlike :meth:`_cleanup_call`, this preserves call-level state such
        as ``_peer_address`` and the reconnect counters so the caller can
        re-dial during an auto-reconnect.
        """
        self._recv_running = False
        self._ping_timer.stop()

        # Stop the send thread (sentinel unblocks the queue immediately)
        self._send_running = False
        if self._send_thread is not None:
            try:
                self._send_queue.put_nowait(None)
            except queue.Full:
                pass
            if self._send_thread is not threading.current_thread():
                self._send_thread.join(timeout=2.0)
            self._send_thread = None

        # Close socket
        if self._call_socket:
            try:
                self._call_socket.close()
            except OSError:
                pass
            self._call_socket = None

        # Stop audio
        self._audio.stop()

        # Clear crypto material — zero the secret bytes before dropping the
        # references so they don't linger in memory longer than necessary.
        wipe_bytes(self._send_key)
        wipe_bytes(self._recv_key)
        wipe_bytes(self._my_private)
        self._send_key = None
        self._recv_key = None
        self._my_private = None
        self._my_public = None
        self._send_seq = 0
        self._last_recv_seq = -1
        self._ping_seq = 0

        # Drop the client object (a re-dial creates a fresh one).
        self._client = None

        # Re-arm the SAS gate for the next connection (no-op when off).
        self._sas_confirmed = not REQUIRE_SAS_CONFIRMATION

    def _cleanup_call(self) -> None:
        """Release all call resources and clear call-level state."""
        self._teardown_connection()

        self._peer_address = None

        # Unmark busy
        self._server.set_busy(False)

        # Clean up deferred / call-scoped state
        self._pending_incoming = None
        self._pending_sas = None
        self._pending_peer_identity = None

        # Reset reconnect bookkeeping for the next call.
        self._is_caller = False
        self._user_ended = False
        self._reconnect_attempts = 0
        self._reconnecting = False

        log.info("Call resources cleaned up")

    # ── Mute passthrough ─────────────────────────────────────────────
    def confirm_sas(self) -> None:
        """Mark the SAS as verified by the user, releasing audio.

        Called from the UI after the user confirms the spoken SAS words
        match on both ends.  Harmless if gating is off or already confirmed.
        """
        if self._sas_confirmed:
            return
        self._sas_confirmed = True
        log.info("SAS confirmed by user — releasing audio")
        self.sas_confirmation_required.emit(False)

    def set_muted(self, muted: bool) -> None:
        """Toggle microphone mute."""
        self._audio.set_muted(muted)
