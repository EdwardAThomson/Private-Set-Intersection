# Private Set Intersection (PSI) C++

C++ port of the PSI protocol reference implementation. The project mirrors the JavaScript workflow (`reference/psiCalculation.js`) using OpenSSL, libsodium, and the Blake3 C implementation, while adding deterministic tests, CLI tooling, and an HTTP endpoint for UI integration.

The previous version of the code (in JS) is included here, but also separately on GitHub: https://github.com/EdwardAThomson/psi-demo.

## Features
- Hash-to-group, H2, ChaCha20-Poly1305, and Blake3-based random derivation aligned with the JS reference.
- Phase-oriented PSI API (`psi_protocol`) with both newline and JSON serialization helpers.
- `psi_demo`: CLI walkthrough of sample units, printing plaintext values, serialized payloads, and per-phase timings.
- `psi_server`: HTTP service exposing `POST /psi`, returning JSON payloads and timing metrics ready for React integration.
- GoogleTest suite covering helper behaviour, serialization round-trips, PSI flows, and error handling.

## Building
```bash
cmake -S . -B build
cmake --build build
cd build && ctest   # run tests
```

## Running the CLI Demo
```bash
./build/psi_demo
```

## Running the HTTP Server
```bash
./build/psi_server
# listens on http://localhost:8080/psi (POST)
```
> Sandbox note: opening sockets is blocked in some restricted environments; run the server on an unrestricted machine.

## HTTP API
### Request
```json
POST /psi
Content-Type: application/json
{
  "bob_units":   [{"id": "u1", "x": 100.0, "y": 100.0}, ...],
  "alice_units": [{"id": "a1", "x": 150.0, "y": 150.0}, ...]
}
```

### Response
```json
{
  "bob_message": {"items": [...]},
  "alice_message": {"items": [...]},
  "bob_response": {"items": [...]},
  "decrypted": ["450 450", ...],
  "timings_ms": {
    "bob_setup": <double>,
    "alice_setup": <double>,
    "bob_response": <double>,
    "alice_finalize": <double>
  }
}
```

## React Integration Sketch
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

## Reports & Docs
- `reports/psi_demo_report.md`: sample CLI run with payloads and timings.
- `reports/progress_2025-10-16.md`: daily progress summary.
- `docs/porting_plan.md`: roadmap, milestones, and API references.

## Front-End Variants
- `reference/`: legacy React demo with automatic JavaScript worker fallback.
- `reference_cpp_only/`: cloned React demo that refuses to run without the C++ `psi_server` backend (JavaScript PSI implementation removed).

## Licenses
Refer to upstream libraries for their respective licenses (OpenSSL, libsodium, Blake3 C implementation).
