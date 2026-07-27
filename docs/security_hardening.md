# Security Hardening Plan: Wire Privacy and Hash-to-Curve

_Status: implemented 2026-07-27 (both issues fixed via Option A, ristretto255) · written 2026-07-27_

This document addresses the two implementation-level security issues identified in the
external review note (`upstream-note-edward-psi.md`): cleartext elements on the wire
(issue 1) and the known-discrete-log `hashToGroup` construction (issue 2). The third
issue raised there, the honest-but-curious trust model, is a protocol-design matter and
is tracked separately in the ROADMAP backlog under dispute resolution.

Both issues also exist in the JavaScript reference implementation
(`reference/psiCalculation.js`), which this port deliberately mirrors. Fixing them
breaks wire and output compatibility with the JS reference. That is the correct trade:
the JS demo should eventually be updated to match, not the other way around.

---

## Issue 1: Cleartext positions travel with every message

### Current behaviour

Every wire message carries the plaintext floored position next to the protected value,
in both serialization formats:

| Message | Cleartext field | Line format | JSON format |
|---|---|---|---|
| Bob's encrypted units | `EncryptedUnit::flooredPosition` | `serialization_utils.cpp:96` | `:321` |
| Alice's blinded values | `AliceSentValue::flooredPosition` | `:132` | `:354` |
| Bob's transformed values | `BobTransformedValue::flooredPosition` | `:160` | `:380` |

The consequence is that both parties' full input sets are readable by the counterparty
and by any observer of the transcript, with no cryptanalysis required. The blinding and
encryption protect nothing while these fields are present.

The field is not purely cosmetic. Two pieces of logic currently depend on it:

1. `aliceFinalizeIntersection` (`psi_protocol.cpp:282`) recognises a successful
   decryption by comparing the ChaCha output against the *received* cleartext
   `encrypted.flooredPosition`.
2. The React visualisations display both sides' positions side by side, which is why
   the field existed in the first place.

### Why the fix is easy here

`chacha_utils.cpp` does not use raw ChaCha20; it uses libsodium's
`crypto_secretbox_easy` / `crypto_secretbox_open_easy` (XSalsa20-Poly1305), which is an
*authenticated* cipher. `chachaDecrypt` already returns `std::nullopt` when the
Poly1305 tag does not verify. A decryption under the wrong key fails authentication
with overwhelming probability, so `decrypted.has_value()` is by itself a reliable
signal of a key match. The cleartext comparison at `psi_protocol.cpp:282` is redundant
and can be deleted along with the field.

(Naming note: this rename has been done. The former `chacha_utils.*` files are now
`src/secretbox_utils.h` / `src/secretbox_utils.cpp`, with `SecretBoxCiphertext`,
`secretboxEncrypt`, and `secretboxDecrypt` replacing the misleading `chacha*` names.
The cipher is libsodium's `crypto_secretbox`, XSalsa20-Poly1305.)

### Changes

1. **Types** (`psi_types.h`): remove `flooredPosition` from `EncryptedUnit`,
   `AliceSentValue`, and `BobTransformedValue`. In `DecryptedUnit`, the position is
   whatever the successful decrypt returns; the separate `flooredPosition` and
   `plaintext` members collapse into one.
2. **Serialization** (`serialization_utils.cpp`): drop the position field from all six
   serializers/deserializers (three message types × two formats). Correlation between
   Alice's sent values and Bob's transformed replies is by index; Bob must preserve
   order (he already does), and Alice already keeps her own
   `AliceSessionState::flooredPositions` locally for anything she needs to know about
   her own set.
3. **Protocol** (`psi_protocol.cpp`): in `aliceFinalizeIntersection`, replace the
   comparison `*decrypted == encrypted.flooredPosition` with a check that
   `chachaDecrypt` returned a value, and take the position from the decrypted
   plaintext.
4. **Frontends**: the visualisations may only display what each side legitimately
   knows: its own set, plus the computed intersection. The side-by-side "both sets"
   view can remain as a *local* demo mode that reads both inputs from the page state,
   not from the wire messages.
5. **Server** (`tools/psi_server.cpp`): the `/psi` endpoint currently plays both roles
   in one process, so its JSON response can keep echoing whatever the demo UI needs,
   but the `bob_message` / `alice_message` / `bob_response` payloads it returns should
   reflect the real (stripped) wire format, otherwise the demo teaches the wrong
   protocol.
6. **Docs**: add a README line stating that messages contain only blinded points and
   ciphertexts, and that earlier versions leaked cleartext.

### Tests

- Round-trip tests in `serialization_utils_test.cpp` updated for the new formats.
- A regression test asserting the serialized forms of all three messages do not
  contain any input position substring.
- Existing end-to-end tests in `psi_protocol_test.cpp` should pass unchanged in
  spirit: same intersections, same non-intersections. Add a case where sets are
  disjoint to confirm finalize returns empty purely via tag failure.

---

## Issue 2: `hashToGroup` has a publicly known discrete log

### The break

`crypto_utils.cpp` maps an element `x` to the curve as:

```
h_x = SHA-512(x)[0..31] mod n     (publicly computable by anyone from x)
P_x = h_x · G
```

So `log_G(P_x) = h_x` is public knowledge for every element in the universe. Bob's
symmetric key for element `y` is `K_y = H2(b · P_y) = H2(h_y · (b·G))`.

Alice legitimately receives `T_i = b · r_i · P_{x_i}` in phase 3 and knows her own
`r_i` and the public `h_{x_i}`, so she computes:

```
(r_i · h_{x_i})^{-1} · T_i = b·G
```

One honest run, one element of her choosing (a fabricated one works), and she holds
`b·G`. From then on she derives `K_y = H2(h_y · (b·G))` for **any** candidate `y`
offline and decrypts Bob's ciphertexts for it. For a 64×64 grid that is ~4,096 scalar
multiplications to enumerate Bob's entire set from a single transcript. The attack is
passive and leaves no evidence, so no dispute-resolution or audit layer can catch it.

Alice's per-element independent blinding scalars (`psi_protocol.cpp:190-194`) do
resist the mirrored attack on her side; the flaw is specific to Bob's key material
having a public linear relationship to `b·G`.

### The fix

Map elements to the group with a construction whose output has *unknown* discrete log.
Then computing `b · P_y` from `b·G` without `log_G P_y` is the Computational
Diffie-Hellman problem, which is exactly the hardness the protocol was meant to rest on.

Two viable routes:

**Option A (recommended): switch the group to ristretto255 via libsodium.**

libsodium, already a dependency, provides everything needed:

- `crypto_core_ristretto255_from_hash(p, h64)`: maps a 64-byte hash to a group
  element via Elligator 2, with no known discrete log. Use
  `crypto_hash_sha512(x)` (or BLAKE3 with a 64-byte output) as the input.
- `crypto_scalarmult_ristretto255(q, n, p)` and
  `crypto_core_ristretto255_scalar_*` replace all the OpenSSL `EC_POINT_mul` /
  `BN_*` machinery, including `crypto_core_ristretto255_scalar_invert` for Alice's
  unblinding and `crypto_core_ristretto255_scalar_random` for key generation.
- ristretto255 is a prime-order group, so there are no cofactor edge cases, and
  encodings are fixed 32-byte strings, which simplifies serialization (currently
  65-byte uncompressed P-256 points).

This removes OpenSSL from the protocol core entirely (it can remain for anything else
that needs it), shrinks `psi_protocol.cpp` considerably by deleting the BIGNUM/EC_POINT
wrapper boilerplate, and is constant-time throughout because inputs (positions) are
secret and libsodium's primitives are designed for that.

**Option B: stay on P-256 and implement RFC 9380.**

The applicable suite is `P256_XMD:SHA-256_SSWU_RO_`. OpenSSL does not expose a public
hash-to-curve API (its internal implementation serves ECH), so this means hand-writing
simplified SWU plus `expand_message_xmd`, roughly 200-300 lines of careful field
arithmetic that must be constant-time. Choose this only if P-256 is a hard external
requirement (for example FIPS constraints or interop with a system pinned to
NIST curves). Nothing in this project imposes that.

Rejected: try-and-increment hashing is variable-time in the secret input, and plain
Elligator 2 on Curve25519 without the ristretto encoding reintroduces cofactor-8
subtleties that ristretto255 exists to remove.

### Changes (Option A)

1. `crypto_utils`: replace `hashToGroup` with SHA-512 → `crypto_core_ristretto255_from_hash`;
   replace `hashPointToKey` with a hash of the 32-byte ristretto encoding (the current
   H2 hashes the encoded point, so the shape survives).
2. `psi_protocol.cpp`: replace `EC_GROUP*`/`BN_CTX*` plumbing and the `BignumPtr` /
   `ECPointPtr` helpers with 32-byte scalar/point arrays and the
   `crypto_scalarmult_ristretto255` calls. The four-phase structure, session state, and
   serialization layering are unchanged.
3. `random_utils` / `deriveRandomValues`: unchanged; outputs feed
   `crypto_core_ristretto255_scalar_reduce` instead of `BN_mod`.
4. Serialization: point fields become fixed 32-byte (base64) strings.
5. Public API: `EC_GROUP*` and `BN_CTX*` disappear from `psi_protocol.h` signatures,
   which also simplifies `psi_demo`, `psi_server`, and every test fixture.

### Tests

- Keep the existing deterministic protocol tests (same-set, disjoint, partial overlap,
  duplicate handling, error paths) on the new group.
- Add a regression test encoding the attack itself: given a full transcript and
  Alice's state, attempt the `(r·h)^{-1}·T` recovery and verify the recovered point
  does **not** predict Bob's key for a fresh element. With `from_hash` there is no
  public `h_x` to use, so the test documents *why* rather than mechanically failing,
  but a comment-anchored test keeps anyone from "simplifying" back to `H(x)·G` later.
  (The upstream reviewers report doing exactly this in their codebase.)
- Vector tests for `hashToGroup` replaced with fixed input/output vectors generated
  once from libsodium, to pin cross-version determinism.

---

## Sequencing

Do issue 2 first, then issue 1, then the frontend updates:

1. The group migration (issue 2) rewrites the internals that issue 1's changes touch;
   doing it first avoids editing the OpenSSL code twice.
2. Both changes break the wire format, so they should land together in one version
   bump, with `reports/` regenerated and the README's API examples updated.
3. The JS reference (`reference/psiCalculation.js` and the upstream psi-demo repo)
   shares both flaws. After the C++ side is fixed, port the same two changes there or
   mark the JS demo as insecure-by-design for visualisation only.

Neither fix addresses malicious inputs (membership-oracle probing); that remains the
dispute-resolution work tracked in the ROADMAP backlog.

---

## Addendum (2026-07-27): key-tag mode

Implemented after the two fixes above. Bob's phase 1 can now send a one-way
membership tag per element, `BLAKE3("PSI-membership-tag-v1" || K_y)`, instead of
`secretbox(K_y, y)`. Alice finalises by hashing her recomputed keys and looking
them up in a set of Bob's tags. Consequences:

- Closes the residual length side channel: secretbox ciphertexts are
  plaintext-length + 16 bytes, so message sizes leaked each element's string
  length; tags are fixed 32 bytes.
- Finalisation drops from O(|Alice| x |Bob|) trial decryptions to O(|Alice|)
  hash lookups. Measured at 5,000 units per side: ~6.1 s vs ~0.29 s
  (see reports/psi_bench_2026-07-27.md).
- Membership correctness rests on BLAKE3 collision resistance instead of the
  Poly1305 forgery bound; both are negligible-failure. The tag derivation is
  domain-separated from the H2 key derivation (different hash function and a
  fixed context prefix).

Both modes coexist in psi_protocol (`runPSIProtocol` vs `runPSIProtocolTags`);
phases 2 and 3 are shared. The server and demo UI still use secretbox mode.
