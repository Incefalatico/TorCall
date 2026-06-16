import logging

from torcall.utils.logger import scrub, _ScrubbingFilter

# A valid-looking v3 onion (56 base32 chars)
ONION = "a" * 56 + ".onion"
SERVICE_ID = "b" * 56


def test_scrub_redacts_onion_and_ip():
    """Onion addresses, service ids and IP literals must be redacted."""
    assert scrub(f"CALL_REQUEST sent to {ONION}") == "CALL_REQUEST sent to <onion>"
    assert scrub(f"Hidden service {SERVICE_ID}") == "Hidden service <onion>"
    assert scrub("Incoming connection from 192.168.1.40") == "Incoming connection from <ip>"
    assert scrub("peer at fe80::1ff:fe23:4567:890a") == "peer at <ip>"


def test_scrub_keeps_ordinary_text():
    """Non-sensitive text is left untouched."""
    assert scrub("Call rejected") == "Call rejected"
    assert scrub("") == ""


def _make_record(msg, args):
    return logging.LogRecord(
        name="torcall", level=logging.INFO, pathname=__file__, lineno=1,
        msg=msg, args=args, exc_info=None,
    )


def test_scrubbing_filter_redacts_message_and_args():
    """The filter scrubs both the format string and positional args."""
    flt = _ScrubbingFilter()

    rec = _make_record("CALL_REQUEST sent to %s", (ONION,))
    flt.filter(rec)
    assert rec.getMessage() == "CALL_REQUEST sent to <onion>"

    rec2 = _make_record(f"connected to {ONION} from %s", ("10.0.0.5",))
    flt.filter(rec2)
    assert rec2.getMessage() == "connected to <onion> from <ip>"


def test_scrubbing_filter_preserves_non_string_args():
    """Numeric args (e.g. key sizes) must survive scrubbing intact."""
    flt = _ScrubbingFilter()
    rec = _make_record("key %d B", (32,))
    flt.filter(rec)
    assert rec.getMessage() == "key 32 B"
