"""
TorCall SOCKS5 client for outgoing calls.

Connects to a remote ``.onion`` hidden service through the local Tor
SOCKS5 proxy, performs the CALL_REQUEST / CALL_ACCEPT handshake, and
surfaces the result to the UI layer via Qt signals.

Usage::

    client = CallClient()
    client.connected.connect(on_connected)
    client.rejected.connect(on_rejected)
    client.connection_failed.connect(on_failed)
    client.connection_timeout.connect(on_timeout)
    client.connect_to("abc...xyz.onion", 7890, my_public_key)
"""

from __future__ import annotations

import socket
from typing import Optional

import socks  # PySocks

from PySide6.QtCore import QObject, QThread, Signal

from torcall.network.protocol import MessageType, Packet, read_packet_sync
from torcall.utils.config import (
    CALL_TIMEOUT_S,
    TCP_BUFFER_SIZE,
    TOR_SOCKS_HOST,
    TOR_SOCKS_PORT,
)
from torcall.utils.logger import log


# ── Worker (runs inside QThread) ─────────────────────────────────────


class _ClientWorker(QObject):
    """
    Background worker that performs the outbound SOCKS5 connection and
    protocol handshake.

    All heavy I/O runs on the owning :class:`QThread` so the main
    (GUI) thread is never blocked.
    """

    connected = Signal(object)
    rejected = Signal()
    connection_failed = Signal(str)
    connection_timeout = Signal()

    def __init__(
        self,
        onion_address: str,
        port: int,
        my_public_key: bytes,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._onion_address = onion_address
        self._port = port
        self._my_public_key = my_public_key
        self._sock: Optional[socks.socksocket] = None
        self._cancelled = False

    # ── main work ────────────────────────────────────────────────────

    def run(self) -> None:
        """
        Connect to the remote peer through Tor and perform the call
        handshake.

        Steps
        -----
        1. Create a SOCKS5 socket pointing at the local Tor proxy.
        2. Connect to ``onion_address:port`` (remote DNS via Tor).
        3. Tune TCP buffers and disable Nagle.
        4. Send a ``CALL_REQUEST`` packet carrying our public key.
        5. Wait for the peer's response.
        6. Emit the appropriate signal depending on the response.
        """
        try:
            # 1. Create SOCKS5 socket
            self._sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.set_proxy(
                socks.SOCKS5,
                TOR_SOCKS_HOST,
                TOR_SOCKS_PORT,
                rdns=True,  # CRITICAL — resolve .onion on the Tor side
            )
            self._sock.settimeout(CALL_TIMEOUT_S)

            log.info(
                "Connecting to %s:%d via SOCKS5 %s:%d …",
                self._onion_address,
                self._port,
                TOR_SOCKS_HOST,
                TOR_SOCKS_PORT,
            )

            # 2. Connect through Tor
            self._sock.connect((self._onion_address, self._port))

            if self._cancelled:
                self._close_socket()
                return

            # 3. Tune socket
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, TCP_BUFFER_SIZE)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, TCP_BUFFER_SIZE)

            # 4. Send CALL_REQUEST
            request = Packet(
                MessageType.CALL_REQUEST,
                sequence=0,
                payload=self._my_public_key,
            )
            self._sock.sendall(request.encode())
            log.info("CALL_REQUEST sent to %s", self._onion_address)

            if self._cancelled:
                self._close_socket()
                return

            # 5. Wait for response
            response = read_packet_sync(self._sock)

            if self._cancelled:
                self._close_socket()
                return

            if response is None:
                log.warning("Peer closed connection without responding")
                self._close_socket()
                self.connection_failed.emit("Peer closed connection without responding")
                return

            # 6. Handle response
            if response.msg_type == MessageType.CALL_ACCEPT:
                peer_public_key = response.payload
                log.info(
                    "Call accepted by %s (key %d B)",
                    self._onion_address,
                    len(peer_public_key),
                )
                self.connected.emit({
                    "socket": self._sock,
                    "peer_public_key": peer_public_key,
                })
                # Socket ownership transfers to the caller — don't close it
                self._sock = None

            elif response.msg_type == MessageType.CALL_REJECT:
                log.info("Call rejected by %s", self._onion_address)
                self._close_socket()
                self.rejected.emit()

            else:
                msg = f"Unexpected response from peer: {response.msg_type.name}"
                log.warning(msg)
                self._close_socket()
                self.connection_failed.emit(msg)

        except socket.timeout:
            log.warning("Connection to %s timed out", self._onion_address)
            self._close_socket()
            self.connection_timeout.emit()

        except Exception as exc:
            if self._cancelled:
                # cancel() was called — swallow the error
                log.debug("Connection cancelled (exception swallowed: %s)", exc)
                self._close_socket()
                return
            msg = f"Connection to {self._onion_address} failed: {exc}"
            log.error(msg)
            self._close_socket()
            self.connection_failed.emit(msg)

    # ── helpers ──────────────────────────────────────────────────────

    def cancel(self) -> None:
        """Cancel an in-progress connection attempt."""
        self._cancelled = True
        self._close_socket()
        log.info("Outgoing connection cancelled")

    def _close_socket(self) -> None:
        """Safely close the underlying socket."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


# ── Public API ───────────────────────────────────────────────────────


class CallClient(QObject):
    """
    SOCKS5 client for placing outgoing TorCall calls via Tor.

    All network I/O runs on a background :class:`QThread`.

    Signals
    -------
    connected(object)
        Emitted when the remote peer accepts the call.  The payload is
        a dict with keys ``socket`` and ``peer_public_key``.
    rejected()
        Emitted when the peer explicitly rejects the call.
    connection_failed(str)
        Emitted on any network or protocol error.  The argument is a
        human-readable error description.
    connection_timeout()
        Emitted when the connection or response exceeds
        ``CALL_TIMEOUT_S``.
    """

    connected = Signal(object)
    rejected = Signal()
    connection_failed = Signal(str)
    connection_timeout = Signal()

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._thread: Optional[QThread] = None
        self._worker: Optional[_ClientWorker] = None

    # ── public methods ───────────────────────────────────────────────

    def connect_to(self, onion_address: str, port: int, my_public_key: bytes) -> None:
        """
        Initiate an outgoing call to *onion_address* on *port*.

        The connection is established through the Tor SOCKS5 proxy at
        ``TOR_SOCKS_HOST:TOR_SOCKS_PORT``.  A ``CALL_REQUEST`` packet
        carrying *my_public_key* is sent, and the peer's response
        determines which signal is emitted.

        Parameters
        ----------
        onion_address:
            The ``.onion`` address of the callee (e.g.
            ``"abc…xyz.onion"``).
        port:
            The TCP port the callee's hidden service is listening on.
        my_public_key:
            Our X25519 public key (32 bytes) to send in the handshake.
        """
        if self._thread is not None:
            log.warning("connect_to() called while a connection is already in progress")
            return

        self._thread = QThread()
        self._worker = _ClientWorker(onion_address, port, my_public_key)
        self._worker.moveToThread(self._thread)

        # Wire worker signals → public signals
        self._worker.connected.connect(self.connected)
        self._worker.rejected.connect(self.rejected)
        self._worker.connection_failed.connect(self.connection_failed)
        self._worker.connection_timeout.connect(self.connection_timeout)

        # Clean up the thread when the worker finishes
        self._worker.connected.connect(self._cleanup_thread)
        self._worker.rejected.connect(self._cleanup_thread)
        self._worker.connection_failed.connect(self._cleanup_thread)
        self._worker.connection_timeout.connect(self._cleanup_thread)

        # Launch
        self._thread.started.connect(self._worker.run)
        self._thread.start()
        log.debug(
            "CallClient QThread started → %s:%d",
            onion_address,
            port,
        )

    def cancel(self) -> None:
        """
        Abort an in-progress connection attempt.

        Closes the socket (which unblocks any blocking I/O) and tears
        down the worker thread.
        """
        if self._worker is not None:
            self._worker.cancel()

        self._cleanup_thread()
        log.info("CallClient cancelled")

    # ── internal ─────────────────────────────────────────────────────

    def _cleanup_thread(self) -> None:
        """Quit and delete the background thread."""
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)
            self._thread = None
        self._worker = None
