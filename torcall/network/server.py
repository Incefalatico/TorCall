"""
TorCall TCP server for incoming calls.

Listens on the hidden-service port for inbound connections and validates
incoming CALL_REQUEST packets before surfacing them to the UI layer via
Qt signals.

Usage::

    server = CallServer()
    server.incoming_call.connect(on_incoming_call)
    server.start(HIDDEN_SERVICE_LOCAL_PORT)
"""

from __future__ import annotations

import socket
import threading
from typing import Optional

from PySide6.QtCore import QObject, QThread, Signal

from torcall.network.protocol import MessageType, Packet, read_packet_sync
from torcall.utils.config import TCP_BUFFER_SIZE
from torcall.utils.logger import log


# ── Worker (runs inside QThread) ─────────────────────────────────────


class _ServerWorker(QObject):
    """
    Background worker that owns the server socket and accept-loop.

    Signals are forwarded to the public :class:`CallServer` instance so
    that UI code only interacts with a single object.
    """

    incoming_call = Signal(object)
    server_started = Signal()
    server_error = Signal(str)

    def __init__(self, port: int, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._port = port
        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._busy = False
        self._lock = threading.Lock()  # guards _busy

    # ── busy state ───────────────────────────────────────────────────

    def set_busy(self, busy: bool) -> None:
        """Mark whether a call is currently active (thread-safe)."""
        with self._lock:
            self._busy = busy
            log.debug("Server busy state → %s", busy)

    def _is_busy(self) -> bool:
        with self._lock:
            return self._busy

    # ── main loop ────────────────────────────────────────────────────

    def run(self) -> None:
        """Bind the server socket and enter the accept loop."""
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.settimeout(1.0)  # so we can check _running
            # Bind to loopback only: the Tor hidden service forwards its
            # remote port to this local port, so nothing outside this host
            # should ever reach it.  Binding 0.0.0.0 would expose the call
            # port to the LAN and allow connections that bypass Tor.
            self._server_socket.bind(("127.0.0.1", self._port))
            self._server_socket.listen(5)
            self._running = True
            log.info("CallServer listening on 127.0.0.1:%d", self._port)
            self.server_started.emit()
        except OSError as exc:
            msg = f"Failed to start server on port {self._port}: {exc}"
            log.error(msg)
            self.server_error.emit(msg)
            return

        while self._running:
            try:
                client_sock, addr = self._server_socket.accept()
            except socket.timeout:
                continue  # check _running flag and loop
            except OSError:
                # Socket was closed externally (stop() called)
                break

            log.info("Incoming connection from %s", addr)
            self._handle_connection(client_sock, addr)

        log.info("CallServer accept loop exited")

    # ── connection handler ───────────────────────────────────────────

    def _handle_connection(self, sock: socket.socket, addr: tuple) -> None:
        """
        Process a single inbound TCP connection.

        * Tunes socket buffers and disables Nagle.
        * Reads the first packet and validates it is a ``CALL_REQUEST``.
        * Rejects the connection if already busy or on protocol error.
        """
        try:
            # Tune socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, TCP_BUFFER_SIZE)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, TCP_BUFFER_SIZE)

            # Read the very first packet
            packet = read_packet_sync(sock)

            if packet is None:
                log.warning("Connection from %s closed before sending a packet", addr)
                sock.close()
                return

            if packet.msg_type != MessageType.CALL_REQUEST:
                log.warning(
                    "Expected CALL_REQUEST from %s, got %s — dropping",
                    addr,
                    packet.msg_type.name,
                )
                sock.close()
                return

            # Reject if already in a call
            if self._is_busy():
                log.info("Rejecting call from %s — already busy", addr)
                reject = Packet(MessageType.CALL_REJECT, sequence=0)
                try:
                    sock.sendall(reject.encode())
                except OSError:
                    pass
                sock.close()
                return

            # Valid CALL_REQUEST — surface to UI
            peer_public_key = packet.payload
            address_str = f"{addr[0]}:{addr[1]}"
            log.info("Valid CALL_REQUEST from %s (key %d B)", addr, len(peer_public_key))

            self.incoming_call.emit({
                "socket": sock,
                "peer_public_key": peer_public_key,
                "address": address_str,
            })

        except Exception as exc:
            log.error("Error handling connection from %s: %s", addr, exc)
            try:
                sock.close()
            except OSError:
                pass

    # ── shutdown ─────────────────────────────────────────────────────

    def stop(self) -> None:
        """Signal the accept loop to exit and close the server socket."""
        self._running = False
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None
        log.info("CallServer socket closed")


# ── Public API ───────────────────────────────────────────────────────


class CallServer(QObject):
    """
    TCP server for receiving incoming TorCall calls.

    Runs the accept loop on a background :class:`QThread` so the UI
    thread is never blocked.

    Signals
    -------
    incoming_call(object)
        Emitted when a valid ``CALL_REQUEST`` arrives.  The payload is a
        dict with keys ``socket``, ``peer_public_key``, and ``address``.
    server_started()
        Emitted once the server socket is bound and listening.
    server_error(str)
        Emitted when the server fails to start or encounters a fatal
        error.
    """

    incoming_call = Signal(object)
    server_started = Signal()
    server_error = Signal(str)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._thread: Optional[QThread] = None
        self._worker: Optional[_ServerWorker] = None

    # ── public methods ───────────────────────────────────────────────

    def start(self, port: int) -> None:
        """
        Start listening for incoming connections on *port*.

        The server socket is opened on ``0.0.0.0:<port>`` inside a
        dedicated :class:`QThread`.
        """
        if self._thread is not None:
            log.warning("CallServer.start() called but server is already running")
            return

        self._thread = QThread()
        self._worker = _ServerWorker(port)
        self._worker.moveToThread(self._thread)

        # Wire worker signals → public signals
        self._worker.incoming_call.connect(self.incoming_call)
        self._worker.server_started.connect(self.server_started)
        self._worker.server_error.connect(self.server_error)

        # Start the worker's run() when the thread begins
        self._thread.started.connect(self._worker.run)

        self._thread.start()
        log.debug("CallServer QThread started for port %d", port)

    def stop(self) -> None:
        """Stop the server and clean up the background thread."""
        if self._worker is not None:
            self._worker.stop()

        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)  # wait up to 5 s for clean exit
            self._thread = None

        self._worker = None
        log.info("CallServer stopped")

    def set_busy(self, busy: bool) -> None:
        """
        Mark whether a call is currently in progress.

        While busy, subsequent ``CALL_REQUEST`` packets are answered
        with a ``CALL_REJECT`` and the socket is closed.
        """
        if self._worker is not None:
            self._worker.set_busy(busy)
