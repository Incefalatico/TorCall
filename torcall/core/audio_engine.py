"""
TorCall audio engine.

Captures audio from the microphone, encodes it with the Opus codec,
decodes incoming Opus frames, and plays them back — all using
thread-safe queues so the real-time audio callback is never blocked.
"""

from __future__ import annotations

import math
import struct
import threading
from collections import deque
from typing import Optional

import numpy as np

from PySide6.QtCore import QObject, Signal

from torcall.utils.config import (
    SAMPLE_RATE,
    CHANNELS,
    FRAME_SIZE,
    AUDIO_DTYPE,
    OPUS_BITRATE,
    JITTER_BUFFER_INITIAL_MS,
    JITTER_BUFFER_MIN_MS,
    JITTER_BUFFER_MAX_MS,
)
from torcall.utils.logger import log

# ── Optional imports ─────────────────────────────────────────────────
try:
    import sounddevice as sd
    _SD_AVAILABLE = True
except ImportError:
    _SD_AVAILABLE = False
    log.warning("sounddevice not found — audio will be unavailable")

# Make a bundled Opus DLL discoverable *before* importing opuslib, which
# resolves the native library at import time.
try:
    from torcall.utils.opus_loader import ensure_opus
    ensure_opus()
except Exception as e:  # noqa: BLE001 — never let the loader crash the app
    log.warning("Opus loader failed (%s)", e)

try:
    import opuslib
    _OPUS_AVAILABLE = True
except Exception as e:  # noqa: BLE001 — opuslib raises non-ImportError if libopus.dll is missing
    _OPUS_AVAILABLE = False
    log.warning("opuslib could not be loaded (%s) — Opus codec will be unavailable", e)


# ── Jitter buffer ────────────────────────────────────────────────────

class JitterBuffer:
    """
    Adaptive jitter buffer.

    Buffers decoded PCM frames and feeds them to the playback callback at
    a steady rate, absorbing network jitter.  The buffer prebuffers up to
    a *target* depth before releasing audio, and adapts that target
    upward when underruns are frequent (and slowly back down when the
    link is stable), keeping latency as low as the network allows.
    """

    def __init__(self) -> None:
        frames_initial = max(1, int(JITTER_BUFFER_INITIAL_MS / 20))
        self._target = frames_initial
        self._min = max(1, int(JITTER_BUFFER_MIN_MS / 20))
        self._max = max(1, int(JITTER_BUFFER_MAX_MS / 20))
        self._buffer: deque[bytes] = deque(maxlen=self._max * 2)
        self._lock = threading.Lock()
        self._silence = b"\x00" * (FRAME_SIZE * CHANNELS * 2)  # 16-bit silence

        # Adaptation state
        self._prebuffering = True       # hold playback until target is reached
        self._underruns = 0             # consecutive underruns since last refill
        self._stable_pops = 0           # successful pops since last underrun

    def push(self, pcm_frame: bytes) -> None:
        """Add a decoded PCM frame to the buffer."""
        with self._lock:
            if len(self._buffer) < self._max * 2:
                self._buffer.append(pcm_frame)

    def pop(self) -> bytes:
        """
        Retrieve the next frame for playback.

        While prebuffering (after start or an underrun) silence is
        returned until the buffer has refilled to the target depth, which
        prevents choppy output.  Returns silence on underrun and grows the
        target depth when underruns recur.
        """
        with self._lock:
            # Prebuffer phase: wait until we have a cushion before playing.
            if self._prebuffering:
                if len(self._buffer) >= self._target:
                    self._prebuffering = False
                else:
                    # Still starved while waiting to fill — count it so a
                    # persistently jittery link grows the target depth.
                    if not self._buffer:
                        self._note_underrun()
                    return self._silence

            if self._buffer:
                self._stable_pops += 1
                # Long stable streak → cautiously shrink target latency.
                if self._stable_pops >= 250 and self._target > self._min:
                    self._target -= 1
                    self._stable_pops = 0
                return self._buffer.popleft()

            # Underrun: re-enter prebuffering and adapt the target upward.
            self._note_underrun()
            self._prebuffering = True
            return self._silence

    def _note_underrun(self) -> None:
        """Record an underrun and grow the target depth if they recur.

        Caller must hold ``self._lock``.
        """
        self._underruns += 1
        self._stable_pops = 0
        if self._underruns >= 3 and self._target < self._max:
            self._target += 1
            self._underruns = 0

    def clear(self) -> None:
        """Flush all buffered frames and reset adaptation state."""
        with self._lock:
            self._buffer.clear()
            self._prebuffering = True
            self._underruns = 0
            self._stable_pops = 0

    @property
    def level(self) -> int:
        """Number of frames currently buffered."""
        with self._lock:
            return len(self._buffer)


# ── Audio engine ─────────────────────────────────────────────────────

class AudioEngine(QObject):
    """
    Real-time audio capture and playback engine.

    Signals:
        audio_captured(bytes): Emitted when a raw PCM frame is captured
            from the microphone (16-bit LE, mono, 48 kHz, 960 samples).
        level_changed(float): RMS audio level from 0.0 to 1.0 for UI meters.
    """

    audio_captured = Signal(bytes)
    level_changed = Signal(float)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)

        self._stream: Optional[sd.Stream] = None if _SD_AVAILABLE else None
        self._encoder = None
        self._decoder = None
        self._muted = False
        self._running = False
        self._jitter = JitterBuffer()

        # Pre-compute silence frame
        self._silence_pcm = b"\x00" * (FRAME_SIZE * CHANNELS * 2)

        self._init_opus()

    # ── Opus codec setup ─────────────────────────────────────────────

    def _init_opus(self) -> None:
        """Initialise Opus encoder and decoder."""
        if not _OPUS_AVAILABLE:
            return
        try:
            self._encoder = opuslib.Encoder(
                SAMPLE_RATE, CHANNELS, opuslib.APPLICATION_VOIP,
            )
            self._encoder.bitrate = OPUS_BITRATE
            self._decoder = opuslib.Decoder(SAMPLE_RATE, CHANNELS)
            log.info("Opus codec initialised (bitrate=%d bps)", OPUS_BITRATE)
        except Exception:
            log.exception("Failed to initialise Opus codec")
            self._encoder = None
            self._decoder = None

    # ── Public API ───────────────────────────────────────────────────

    def start(self) -> None:
        """Open the audio stream and begin capture/playback."""
        if not _SD_AVAILABLE:
            log.error("Cannot start audio — sounddevice is not available")
            return
        if self._running:
            return

        try:
            self._stream = sd.Stream(
                samplerate=SAMPLE_RATE,
                channels=CHANNELS,
                dtype=AUDIO_DTYPE,
                blocksize=FRAME_SIZE,
                callback=self._audio_callback,
            )
            self._stream.start()
            self._running = True
            log.info("Audio stream started (rate=%d, blocksize=%d)", SAMPLE_RATE, FRAME_SIZE)
        except Exception:
            log.exception("Failed to start audio stream")

    def stop(self) -> None:
        """Stop and close the audio stream."""
        self._running = False
        if self._stream is not None:
            try:
                self._stream.stop()
                self._stream.close()
            except Exception:
                log.exception("Error closing audio stream")
            self._stream = None
        self._jitter.clear()
        log.info("Audio stream stopped")

    @property
    def is_muted(self) -> bool:
        return self._muted

    def set_muted(self, muted: bool) -> None:
        """Toggle microphone mute."""
        self._muted = muted
        log.info("Microphone %s", "muted" if muted else "unmuted")

    # ── Opus helpers ─────────────────────────────────────────────────

    def encode(self, pcm_data: bytes) -> bytes:
        """Encode raw PCM (16-bit LE, mono) to an Opus packet."""
        if self._encoder is None:
            return pcm_data  # passthrough if Opus unavailable
        return self._encoder.encode(pcm_data, FRAME_SIZE)

    def decode(self, opus_data: bytes) -> bytes:
        """Decode an Opus packet to raw PCM."""
        if self._decoder is None:
            return opus_data
        return self._decoder.decode(opus_data, FRAME_SIZE)

    def play(self, pcm_data: bytes) -> None:
        """Enqueue a decoded PCM frame for playback via the jitter buffer."""
        self._jitter.push(pcm_data)

    # ── Sounddevice callback (runs in audio thread) ──────────────────

    def _audio_callback(self, indata: np.ndarray, outdata: np.ndarray,
                        frames: int, time_info, status) -> None:
        """
        Called by sounddevice for every audio block.

        *indata*  — captured microphone samples (numpy int16 array).
        *outdata* — buffer to fill with playback samples.
        """
        if status:
            log.debug("Audio status: %s", status)

        # ── Capture (input) ──────────────────────────────────────────
        if self._muted:
            capture_bytes = self._silence_pcm
        else:
            capture_bytes = indata.tobytes()

        # Calculate RMS level (0.0 – 1.0)
        try:
            samples = indata[:, 0].astype(np.float32) if not self._muted else np.zeros(frames, dtype=np.float32)
            rms = float(np.sqrt(np.mean(samples ** 2)) / 32768.0)
            rms = min(1.0, rms * 3.0)  # amplify for visibility
            self.level_changed.emit(rms)
        except Exception:
            pass

        # Emit captured audio for encoding and sending
        self.audio_captured.emit(capture_bytes)

        # ── Playback (output) ────────────────────────────────────────
        playback_bytes = self._jitter.pop()
        try:
            playback_array = np.frombuffer(playback_bytes, dtype=np.int16).reshape(-1, CHANNELS)
            outdata[:] = playback_array[:frames]
        except ValueError:
            outdata[:] = 0
