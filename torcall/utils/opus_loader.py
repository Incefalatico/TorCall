"""
Opus native library loader.

``opuslib`` resolves the native Opus codec at import time via
``ctypes.util.find_library('opus')``, which on Windows only searches the
``PATH``.  A typical desktop install has no ``opus.dll`` on the ``PATH``,
so the import fails and the app silently falls back to sending raw,
unencoded PCM (≈16× the bandwidth — unusable over Tor).

This module makes a bundled Opus DLL discoverable *before* ``opuslib`` is
imported.  Call :func:`ensure_opus` once, early, then import ``opuslib``.

Drop a DLL named ``opus.dll`` (or ``libopus-0.dll`` / ``libopus.dll``)
into the project ``lib/`` directory (see ``NATIVE_LIB_DIR``).  Use
``scratch/download_opus.py`` to fetch one automatically.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
from typing import Optional

from torcall.utils.config import NATIVE_LIB_DIR
from torcall.utils.logger import log

# Candidate filenames, in priority order. ``find_library('opus')`` matches
# the first, but Opus is distributed under several names on Windows.
_CANDIDATES = ("opus.dll", "libopus-0.dll", "libopus.dll", "libopus.so", "libopus.dylib")

_ensured = False


def _find_bundled_dll() -> Optional[str]:
    """Return the path of a bundled Opus library, or None if absent."""
    if not os.path.isdir(NATIVE_LIB_DIR):
        return None
    for name in _CANDIDATES:
        candidate = os.path.join(NATIVE_LIB_DIR, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def ensure_opus() -> bool:
    """Make a bundled Opus library discoverable by ``opuslib``.

    Must be called *before* ``import opuslib``.  Returns True if a usable
    library was located (bundled or already on the system), False
    otherwise.  Safe to call multiple times.
    """
    global _ensured
    if _ensured:
        return True

    dll_path = _find_bundled_dll()

    if dll_path is None:
        # Nothing bundled — fall back to whatever the system provides.
        if ctypes.util.find_library("opus"):
            _ensured = True
            return True
        log.warning(
            "No bundled Opus library found in %s and none on the system. "
            "Run scratch/download_opus.py to fetch one.",
            NATIVE_LIB_DIR,
        )
        return False

    lib_dir = os.path.dirname(dll_path)

    # 1) Make the directory searchable for dependent DLLs (Windows).
    if hasattr(os, "add_dll_directory"):
        try:
            os.add_dll_directory(lib_dir)
        except OSError:
            log.exception("Could not register DLL directory %s", lib_dir)

    # 2) Prepend to PATH so find_library / loader can see it.
    os.environ["PATH"] = lib_dir + os.pathsep + os.environ.get("PATH", "")

    # 3) Verify the DLL actually loads (catches arch mismatches early).
    try:
        ctypes.CDLL(dll_path)
    except OSError:
        log.exception("Found Opus library at %s but it failed to load", dll_path)
        return False

    # 4) Patch find_library so opuslib resolves to our exact file even if
    #    its basename isn't the canonical 'opus.dll'.
    _patch_find_library(dll_path)

    log.info("Opus library located: %s", dll_path)
    _ensured = True
    return True


def _patch_find_library(dll_path: str) -> None:
    """Force ``find_library('opus')`` to return *dll_path*."""
    original = ctypes.util.find_library

    def _patched(name: str):
        if name == "opus":
            return dll_path
        return original(name)

    ctypes.util.find_library = _patched
