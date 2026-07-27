# Roadmap — Private Set Intersection (PSI) C++

_Status: active · updated 2026-05-30_

A modern C++ port of the Private Set Intersection protocol (libsodium ristretto255 +
BLAKE3), mirroring the JavaScript reference in the sibling `psi-demo` repo and
adding HTTP networking, deterministic tests, and timing instrumentation. See
`docs/porting_plan.md` for the detailed plan.

## Shipped

- [x] Core protocol — ristretto255 hash-to-group (unknown discrete log), H2, authenticated
      secretbox encryption, BLAKE3 PRNG (deliberately diverges from the JS reference,
      which has a known-discrete-log break; see `docs/security_hardening.md`)
- [x] Security fix: replaced `H(x)·G` hash-to-group with ristretto255 `from_hash`,
      removing the offline set-enumeration attack (2026-07-27)
- [x] Security fix: removed cleartext positions from all wire messages; decrypt success
      now detected via the secretbox auth tag (2026-07-27)
- [x] Key-tag protocol mode: Bob sends BLAKE3 membership tags instead of ciphertexts;
      finalisation becomes O(A) hash lookups instead of O(A x B) trial decryptions, and
      fixed 32-byte tags close the element-length leak (2026-07-27)
- [x] `psi_bench` tool comparing both modes; at 5,000 units/side tag-mode finalise is
      ~21x faster (see `reports/psi_bench_2026-07-27.md`)
- [x] Threat model documented in README (honest-but-curious)
- [x] 4-phase Bob/Alice protocol with explicit session state
- [x] CLI demo (`psi_demo`) with base64 payloads + per-phase timing
- [x] HTTP server (`psi_server`) exposing `POST /psi` (JSON unit arrays)
- [x] Dual serialization (newline-delimited + JSON) with round-trip validation
- [x] GoogleTest suite (crypto helpers, serialization, end-to-end flows, error paths)
- [x] C++-only React frontend (Web Worker proxy, strict no-JS-fallback)
- [x] Legacy React frontend with automatic JS fallback
- [x] Per-phase performance metrics on all responses
- [x] CORS support
- [x] CMake build (auto libsodium detection, vendored BLAKE3; OpenSSL no longer required)

## Next

- [ ] Benchmark C++ vs JS worker latency on larger datasets (C++ mode-vs-mode
      benchmarking done via `psi_bench`; the JS comparison remains)
- [ ] Decide whether tag mode becomes the default for `psi_server` and the demo UI
- [ ] Multi-threading / SIMD for BLAKE3 (performance, post-correctness)

## Backlog

- [ ] WebAssembly or desktop variant to cut browser-call latency
- [ ] Dispute-resolution protocol for malicious inputs. End-of-game position reveal
      alone is insufficient: nothing binds PSI messages to revealed positions, so a
      cheater can probe with fabricated inputs and reveal honest ones. Required
      pieces: (1) hash commitment to input set + PRNG seed published before the
      exchange, (2) all blinding scalars derived deterministically from the committed
      seed (BLAKE3 `deriveRandomValues` already fits), (3) signed transcripts, so
      (4) an after-the-fact audit can recompute every byte either party should have
      sent, making a fabricated input attributable, punishable evidence. This is
      deterrence, not prevention: the protocol stays private against
      honest-but-curious parties; malicious probing becomes provable after the fact.
      Inspiration: interactive verification / fraud-proof designs (Truebit, Cartesi,
      Xaya game channels).
- [ ] Pad input sets to a fixed size with dummy elements indistinguishable from real
      ones, so set cardinality stops leaking from message length
- [ ] Multi-dataset scalability testing (larger unit / visibility sets)
- [ ] Port the two security fixes to the JS demo (psi-demo repo), or mark it
      visualisation-only
