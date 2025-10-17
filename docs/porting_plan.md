# PSI C++ Porting Plan

## Goal
Recreate the PSI workflow implemented in `reference/psiCalculation.js` in modern C++ using OpenSSL (EC math), libsodium (ChaCha20-Poly1305, random utilities), and BLAKE3 (hash-based PRNG). The end result should enable deterministic intersection results that match the behaviour of the JavaScript reference.

## Current State
- Hash-to-group, H2, ChaCha20-Poly1305, and BLAKE3 random derivation all mirror the JS reference.
- `psi_protocol.{h,cpp}` implements the PSI phases plus serialization helpers for both newline and JSON formats.
- `psi_demo` (CLI) and `psi_server` (HTTP) exercise the protocol and expose JSON payloads ready for UI integration.
- GoogleTest suite covers helpers, serialization formats, end-to-end PSI flows, and error paths (bad base64/JSON/headers).
- React reference UI now targets the C++ `psi_server` over HTTP by default, falling back to the JS worker if the backend is unavailable.

## Dependency Checklist
1. **OpenSSL** — already in use for curve operations.
2. **libsodium** — linked; needs runtime initialisation (`sodium_init`) and wrappers for ChaCha20-Poly1305 and constant-time comparisons.
3. **BLAKE3** — vendored C implementation compiled in portable mode; helper available via `blake3Hash`.

## Porting Steps
1. **Align Hash-To-Group Behaviour**
   - Match JS logic: UTF-8 input → `nacl.hash` (SHA-512) → first 32 bytes as scalar.
   - Use libsodium’s `crypto_hash_sha512` or OpenSSL to reproduce SHA-512 output.
   - Reduce scalar mod curve order; zero-check and retry as needed.

2. **Implement H2 (Point → Symmetric Key)**
   - Encode EC points in uncompressed form using `EC_POINT_point2oct`.
   - Hash via libsodium SHA-512 (or BLAKE3 if matching JS change is acceptable) and truncate to 32 bytes.
   - Return `std::array<uint8_t, 32>` for direct use as symmetric keys.

3. **ChaCha20-Poly1305 Helpers**
   - Wrap `crypto_secretbox_easy/open` (24-byte nonce, 32-byte key) to mirror TweetNaCl behaviour.
   - Ensure inputs/outputs use base64 or raw bytes depending on the final interface needs.
   - Add deterministic test vectors.

4. **Random Value Derivation**
   - Implement `deriveRandomValues` using BLAKE3: `hash(seed)` iteratively to produce big integers.
   - Convert each 32-byte digest into scalar (`BIGNUM` or libsodium scalar API), storing alongside raw bytes if needed.

5. **Protocol Orchestration** *(done)*
   - `psi_protocol` exposes Bob/Alice message phases, serialization-ready structs, and `runPSIProtocol` for tests.

6. **Testing Strategy** *(done)*
   - GoogleTest validates helpers, serialization (newline + JSON), PSI flows, and error handling.

7. **Performance & Safety** *(ongoing)*
   - Extensive error checking, deterministic randomness, and base64 sanitisation already in place.
   - Next step: benchmark C++ vs. JS worker once the React UI targets the HTTP API.

## Suggested Milestones
1. Helpers complete (Steps 1–4) with unit tests.
2. Basic PSI round-trip for small dataset (Step 5).
3. Robust testing and clean-up (Step 6 & 7).
4. Wire the React UI to `psi_server` (`POST /psi`) and capture latency metrics.
5. Optional: multi-threading or SIMD BLAKE3 once correctness is validated.

## Runtime Targets
- `psi_demo`: CLI that prints plaintext units, JSON payloads, and per-phase timings for the sample dataset.
- `psi_server`: HTTP endpoint (`POST /psi`) returning the same JSON payloads/timings for consumption by the React UI or other clients.

## HTTP API Quick Reference
- **Endpoint**: `POST /psi`
- **Request Body** (`application/json`):

  ```json
  {
    "bob_units": [{"id": "u1", "x": 100.0, "y": 100.0}, ...],
    "alice_units": [{"id": "a1", "x": 150.0, "y": 150.0}, ...]
  }
  ```

- **Response Body**:

  ```json
  {
    "bob_message": {"items": [...]},
    "alice_message": {"items": [...]},
    "bob_response": {"items": [...]},
    "decrypted": ["450 450", ...],
    "timings_ms": {
      "bob_setup": 0.32,
      "alice_setup": 0.78,
      "bob_response": 0.65,
      "alice_finalize": 0.83
    }
  }
  ```

- **React Integration Sketch**:

  ```js
  async function runPsi(bobUnits, aliceUnits) {
    const res = await fetch('http://localhost:8080/psi', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bob_units: bobUnits, alice_units: aliceUnits })
    });
    if (!res.ok) throw new Error('PSI request failed');
    return res.json();
  }
  ```

> **Sandbox note**: Opening a listening socket is blocked here (`socket: Operation not permitted`), so run `psi_server` plus integration tests on an unrestricted machine.

## Open Questions
- Do we need interoperability with existing serialized data (base64 strings, JSON protocols)?
- Should final output keep JS structure (`{unit, ciphertext, nonce}` etc.) or adopt C++ domain-specific structs?
- Are there constraints on deterministic randomness seeding for reproducible tests?

Document updates as each milestone is delivered.
