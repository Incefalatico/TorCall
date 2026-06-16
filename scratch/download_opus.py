"""
Download the Opus codec DLL for TorCall (Windows x86-64).

``opuslib`` needs a native ``opus`` library at runtime, which is not
shipped with the Python wheel.  This helper fetches the official MSYS2
build of libopus, verifies its SHA-256, extracts ``libopus-0.dll`` and
installs it into the project ``lib/`` directory as ``opus.dll`` so that
:func:`torcall.utils.opus_loader.ensure_opus` can pick it up.

Usage::

    python scratch/download_opus.py

Re-run to refresh. Safe to run multiple times.
"""

import hashlib
import io
import os
import ssl
import subprocess
import sys
import tarfile
import urllib.request

# ── Pinned MSYS2 package (x86-64) ─────────────────────────────────────
# Source: https://packages.msys2.org/package/mingw-w64-x86_64-opus
PKG_URL = (
    "https://mirror.msys2.org/mingw/mingw64/"
    "mingw-w64-x86_64-opus-1.6.1-1-any.pkg.tar.zst"
)
PKG_SHA256 = "8ff5a273c811e64c5af4c886b6f5d7a8aefca30ef2c7942a7e0a7e62c49e1c25"

# File inside the archive and the name we install it under.
MEMBER_NAME = "mingw64/bin/libopus-0.dll"
INSTALL_NAME = "opus.dll"

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LIB_DIR = os.path.join(ROOT_DIR, "lib")


def _ensure_zstandard():
    """Import zstandard, installing it on the fly if missing."""
    try:
        import zstandard  # noqa: F401
        return __import__("zstandard")
    except ImportError:
        print("Installing 'zstandard' (needed to unpack the .zst archive)…")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "zstandard"]
        )
        return __import__("zstandard")


def _download(url: str) -> bytes:
    print(f"Downloading Opus package:\n  {url}")
    # NOTE: Some MSYS2 mirrors serve expired TLS certs. We don't rely on TLS
    # for authenticity here — the pinned SHA-256 below is what guarantees the
    # file is genuine and untampered, so certificate verification is disabled.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    )
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
        total = int(resp.headers.get("content-length", 0))
        read = 0
        chunks = []
        block = 64 * 1024
        while True:
            chunk = resp.read(block)
            if not chunk:
                break
            chunks.append(chunk)
            read += len(chunk)
            if total:
                pct = min(100, read * 100 // total)
                sys.stdout.write(f"\r  {pct}% ({read}/{total} bytes)")
            else:
                sys.stdout.write(f"\r  {read} bytes")
            sys.stdout.flush()
    print("\nDownload complete.")
    return b"".join(chunks)


def main() -> int:
    data = _download(PKG_URL)

    digest = hashlib.sha256(data).hexdigest()
    if digest != PKG_SHA256:
        print("ERROR: SHA-256 mismatch — refusing to use this download.")
        print(f"  expected: {PKG_SHA256}")
        print(f"  actual:   {digest}")
        return 1
    print("SHA-256 verified.")

    zstd = _ensure_zstandard()
    print("Decompressing archive…")
    dctx = zstd.ZstdDecompressor()
    tar_bytes = dctx.decompress(data, max_output_size=64 * 1024 * 1024)

    print(f"Extracting {MEMBER_NAME}…")
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tar:
        try:
            member = tar.getmember(MEMBER_NAME)
        except KeyError:
            print(f"ERROR: {MEMBER_NAME} not found in archive. Contents:")
            for m in tar.getmembers()[:40]:
                print("  -", m.name)
            return 1
        src = tar.extractfile(member)
        if src is None:
            print("ERROR: could not read DLL from archive.")
            return 1
        dll_data = src.read()

    os.makedirs(LIB_DIR, exist_ok=True)
    dest = os.path.join(LIB_DIR, INSTALL_NAME)
    with open(dest, "wb") as fh:
        fh.write(dll_data)

    print(f"\nInstalled Opus DLL → {dest} ({len(dll_data)} bytes)")
    print("Done. Restart TorCall to enable the Opus codec.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
