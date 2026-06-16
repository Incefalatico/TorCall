import pytest
from torcall.core.audio_engine import JitterBuffer, AudioEngine

def test_jitter_buffer():
    """Verify push, pop, level, clear, and adaptive prebuffering behavior."""
    jb = JitterBuffer()
    silence_len = 960 * 1 * 2  # FRAME_SIZE * CHANNELS * 2 bytes (16-bit)

    # Initially empty, should return silence (all zeros)
    silence = jb.pop()
    assert len(silence) == silence_len
    assert silence == b"\x00" * silence_len
    assert jb.level == 0

    # The buffer prebuffers up to its target depth before releasing audio,
    # so a single pushed frame is held back (silence returned) until the
    # cushion is filled.
    target = jb._target
    frames = [bytes([i + 1]) * silence_len for i in range(target)]
    for i, f in enumerate(frames[:-1]):
        jb.push(f)
        assert jb.pop() == b"\x00" * silence_len  # still prebuffering

    # Pushing the final frame reaches the target → playback starts in order.
    jb.push(frames[-1])
    assert jb.level == target
    for f in frames:
        assert jb.pop() == f

    # Drained → underrun returns silence again.
    assert jb.pop() == b"\x00" * silence_len

    # Clear resets everything including adaptation state.
    jb.push(frames[0])
    jb.clear()
    assert jb.level == 0
    assert jb.pop() == b"\x00" * silence_len


def test_jitter_buffer_adapts_target_on_underruns():
    """Repeated underruns should grow the target buffer depth."""
    jb = JitterBuffer()
    start_target = jb._target
    # Force several underruns (empty buffer pops).
    for _ in range(10):
        jb.pop()
    assert jb._target > start_target
    assert jb._target <= jb._max

def test_audio_engine_opus_codec():
    """Verify Opus encoding/decoding if the library is available, or fallback passthrough."""
    engine = AudioEngine()
    
    # Create mock 16-bit PCM frame (960 samples, mono = 1920 bytes)
    dummy_pcm = b"\x00\x05" * 960
    
    # Test encoding
    encoded = engine.encode(dummy_pcm)
    assert len(encoded) > 0
    
    # Test decoding
    decoded = engine.decode(encoded)
    assert len(decoded) == len(dummy_pcm)
    
    # If Opus is available, the encoded size should be much smaller (compression)
    from torcall.core.audio_engine import _OPUS_AVAILABLE
    if _OPUS_AVAILABLE:
        assert len(encoded) < len(dummy_pcm)
        # Verify round-trip content (not exactly same due to lossy codec, but similar shape)
        assert len(decoded) == len(dummy_pcm)
    else:
        # If fallback, it should be exact passthrough
        assert encoded == dummy_pcm
        assert decoded == dummy_pcm
