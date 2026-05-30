# Roadmap — Private Set Intersection (PSI) C++

_Status: active · updated 2026-05-30_

A modern C++ port of the Private Set Intersection protocol (OpenSSL + libsodium +
BLAKE3), mirroring the JavaScript reference in the sibling `psi-demo` repo and
adding HTTP networking, deterministic tests, and timing instrumentation. See
`docs/porting_plan.md` for the detailed plan.

## Shipped

- [x] Core protocol — hash-to-group, H2, ChaCha20-Poly1305, BLAKE3 PRNG (matches JS reference)
- [x] 4-phase Bob/Alice protocol with explicit session state
- [x] CLI demo (`psi_demo`) with base64 payloads + per-phase timing
- [x] HTTP server (`psi_server`) exposing `POST /psi` (JSON unit arrays)
- [x] Dual serialization (newline-delimited + JSON) with round-trip validation
- [x] GoogleTest suite (crypto helpers, serialization, end-to-end flows, error paths)
- [x] C++-only React frontend (Web Worker proxy, strict no-JS-fallback)
- [x] Legacy React frontend with automatic JS fallback
- [x] Per-phase performance metrics on all responses
- [x] CORS support
- [x] CMake build (auto libsodium/OpenSSL detection, vendored BLAKE3)

## Next

- [ ] Benchmark C++ vs JS worker latency on larger datasets
- [ ] Multi-threading / SIMD for BLAKE3 (performance, post-correctness)

## Backlog

- [ ] WebAssembly or desktop variant to cut browser-call latency
- [ ] Dispute-resolution protocol (reveal positions at game end)
- [ ] Multi-dataset scalability testing (larger unit / visibility sets)
