# TorCall — Encrypted Voice Calls over Tor

TorCall is a modern, secure, peer-to-peer desktop application for making encrypted voice calls over the Tor network, developed in Python 3.11, PySide6 (Qt), and Tor Hidden Services.

It allows users to call each other anonymously by simply exchanging ephemeral `.onion` addresses.

---

## 🔒 Security and Design Features

* Anonymity: All connections are routed through the Tor network. The location and IP address of the caller and recipient are hidden using Tor's onion routing.
* End-to-End Encryption (E2EE):
* Key Exchange: Ephemeral X25519 (ECDH) key pair generated for each call.
* **Key Derivation**: Two distinct directional keys are derived from the ECDH secret via **HKDF-SHA256** (one for the calling→receiving flow, one for the receiving→calling flow). Using separate keys for the two directions avoids reuse of the AES-GCM nonce, since both peers start their packet counters at 0.
* **Encryption**: Audio streams are encrypted packet-by-packet via **AES-256-GCM** with a unique 12-byte nonce (structured as an 8-byte monotonic big-endian sequential counter padded with zeros).
* **Anti-replay**: The receiver keeps track of the last audio sequence accepted and discards duplicate or out-of-order packets; the counter is only incremented after a successful authenticated decryption.
* **Anti-MITM Verification (SAS)**: The ephemeral X25519 exchange protects against passive eavesdroppers but not against an active man-in-the-middle forwarding the handshake. At the beginning of each call, the app displays a **Short Authentication String** (4 words) derived from the public keys of both peers. The two parties compare these by voice, and if they do not match, the call is compromised and must be terminated.
* **Persistent Identity and Contact Recognition**:
* **Long-Term Ed25519 Identity**: In addition to the per-call ephemeral keys, each installation generates a persistent **Ed25519** key pair. At each handshake, the ephemeral X25519 key is **signed** with the long-term identity, so the peer can verify that whoever controls the `.onion` address also controls the recognized identity.
* **Contact Pinning (Trust-On-First-Use)**: The first time a call is made to an address, the peer's identity is pinned. If the identity associated with that address changes in a subsequent call, the app displays a `⚠ IDENTITY CHANGED` warning — just like SSH does with host keys — signaling a possible MITM or identity rotation that needs to be verified.
* **Readable Fingerprint**: Each identity is summarized in a grouped hexadecimal fingerprint (e.g., `a1:b2:c3:…`) displayed in the call.
* **Address Book**: Pinned contacts are available in an address book from which you can rename them, copy their address for recall, or remove them. Removing them deletes any `.onion` addresses associated with the same identity (useful if the contact has rotated addresses while maintaining the key) and is protected by explicit confirmation.
* **Secret-at-rest protection**:
* **Passphrase encryption**: The hidden service identity, Ed25519 identity, and the contact database are encrypted on disk with **scrypt** (passphrase stretching) + **AES-256-GCM** when the `TORCALL_PASSPHRASE` environment variable is set. If no passphrase is set, cleartext storage is used with a warning (for backward compatibility), relying on the operating system's file permissions.
* **Memory hygiene**: Session keys and ephemeral private keys are held in mutable `bytearrays` and reset at the end of the call, to reduce secret persistence in memory.
* **Traffic Analysis Resistance**:
* **Block Padding**: Each encrypted audio frame is padded to a multiple of `TRAFFIC_PAD_BLOCK` (256 bytes) before encryption, so all packet sizes collapse to a few fixed values. This hides Opus's variable bitrate (VBR) signal, which would otherwise reveal *when* someone is speaking even if the content is encrypted.
* **Constant Rate**: In `CONSTANT_RATE_SEND` mode (on by default), audio packets are transmitted at a fixed rate (one frame every 20 ms), and **silence frames** are sent during moments of silence, so an observer cannot infer the timing of speech from the packet timing. This can be disabled with `TORCALL_CONSTANT_RATE=0` to save bandwidth at the expense of temporal privacy.
* **Log Hygiene**:
* Logs are **console-only** by default (file logging is opt-in via `TORCALL_LOG_FILE=1`), and an automatic filter **obscures** `.onion` addresses, service IDs, and IPv4/IPv6 addresses from messages, preventing sensitive data from accidentally ending up in the logs.
* **Audio Management**:
* Microphone Capture
