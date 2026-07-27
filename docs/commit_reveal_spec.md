# Commit-Reveal Dispute Protocol: Draft Specification

_Status: draft v0.1 · sketch complete, details being filled in · phase 1 of section 9 (derivation mode, transcript container, `psi_audit` CLI, padding and commitment helpers) is implemented in this repo · see `docs/dispute_resolution_notes.md` for background and provenance_

This document specifies the commit-reveal layer that binds the PSI fog-of-war
protocol to committed game state, so that a fabricated PSI input becomes signed,
provable, punishable evidence. Sections marked **TBD** are open decisions; the
intent is to resolve them in place so this document converges on an
implementable spec.

## 1. Goal and non-goals

**Goal.** After a game (or on challenge during one), an auditor holding the
signed message transcript and the loser-of-the-dispute's opened commitments can
recompute every byte that party should have sent, compare against what they did
send, and produce a verdict: honest, or fraud with a pointer to the first
mismatching byte. Cheating is not prevented in the moment; it is made
attributable and economically irrational.

**Non-goals.** Preventing information learned before slashing (bonds must price
this in); policing out-of-band collusion; hiding information the protocol
legitimately reveals (the intersection, the padded set size, coarse-level
co-occupancy in the mesh cascade).

## 2. Parties and setting

The core of this spec (sections 3 to 7) is transport-agnostic: two players `P`
and `Q`, a bonded on-chain contract holding stakes and the game rules,
deterministic game physics, every protocol message signed by its sender, both
parties retaining the full transcript. Each turn runs the fog-of-war query in
both directions (each player takes the Bob role for their own set and the Alice
role against the other's), over the multi-level mesh cascade. The PSI
relationship is inherently pairwise, so a room of `n` players is at most
`n(n-1)/2` independent instances of this spec, not one `n`-party instance.

PSI runs only between *unfriendly* pairs. Allied players (PVE co-op
teammates) share vision by consent, out of band, and need no PSI between
them. In practice this keeps the instance count well below the pairwise
maximum and concentrates the protocol exactly where the adversarial trust
model applies: PVP encounters and unallied strangers sharing a segment.

Two deployment profiles, both reusing Xaya technology where it saves work:

- **Channelized 1v1** (fast-tick games, e.g. RTS): each pair runs inside a Xaya
  game channel (the approach pioneered by Xayaships). Instant bilateral
  finality; abort and timeout semantics come from the channel framework.
- **GSP-arbitrated rooms** (turn-based multiplayer, e.g. xayaroguelike): pairs
  exchange signed PSI flights over any off-chain transport; only commitments
  are periodically anchored on-chain. Disputes are submitted as ordinary chain
  moves and the game's GSP (Game State Processor) executes the audit as part of
  its state transition. This is the direct continuation of the 2020 blog's
  design (on-chain commitments plus deterministic GSP replay), extended to the
  PSI transcript.

## 3. Key and seed hierarchy

All protocol randomness for the whole game derives from one master secret per
player.

```
k_P                    32-byte master key, generated at game start, kept secret
com_k_P = H(k_P)       published on-chain at setup
seed_P(t)              = BLAKE3-derive_key(context = "PSI-turn-seed-v1",
                          material = k_P || LE64(t))
subseed_P(t, lvl, dir, role)
                       = BLAKE3-derive_key(context = "PSI-subseed-v1",
                          material = seed_P(t) || LE32(lvl) || dir || role)
```

`dir` is one byte (0: P queries Q, 1: Q queries P); `role` is one byte
(0: Bob-role scalar, 1: Alice-role blinding chain, 2: dummy padding, 3: salt).
`H` is BLAKE3 with context `"PSI-commit-v1"`. **TBD:** exact context strings to
be frozen at v1.0; changing any of them afterwards is a hard fork of the audit.

Derived values:

- **Bob-role private scalar** for `(t, lvl, dir)`:
  `scalarFromDerived(subseed(t, lvl, dir, 0))` (existing reduction in
  `psi_protocol.cpp`, non-zero guaranteed).
- **Alice-role blinding scalars**: the existing BLAKE3 chain
  `deriveRandomValues(count, subseed(t, lvl, dir, 1))`, each reduced by
  `scalarFromDerived`. `count` is the fixed padded size (section 6), so the
  chain length is not input-dependent.
- **Commitment salt**: `subseed(t, lvl, dir, 3)`.

Consequence: given `k_P` and the turn's true input set, every byte of every
message `P` sends is recomputable by anyone. The existing `deriveRandomValues`
is already the right primitive; the implementation work is a derivation mode
that replaces the `randombytes_buf` calls behind an explicit opt-in
(section 9).

## 4. Commitments

Per turn, before any PSI flight:

```
C_P(t) = H( canonical(S_P(t)) || H(seed_P(t)) || subseed_P(t, 0, 0, 3) )
```

where `canonical(S)` is the sorted, newline-joined list of the player's
occupied finest-level cell strings. Exchanged as the turn's first signed
message. The initial commitment `C_P(0)` goes on-chain at setup.

Binding `H(seed_P(t))` into the per-turn commitment settles the seed-opening
granularity question: opening turn `t` means revealing `(S_P(t), seed_P(t))`
and checking them against `C_P(t)`; the salt is derived from the revealed
seed. Exactly one turn's randomness (and therefore one turn's positions, see
the disclosure note in section 8) is exposed per dispute. No Merkle tree over
per-turn seeds, no VRF, and no reveal of `k_P` is needed; the master key is
demoted to a derivation convenience, and its on-chain commitment `com_k_P`
becomes optional (useful only for a full end-of-game reveal, which the 2020
design already envisages).

**TBD:** whether per-turn commitments also need periodic on-chain checkpoints
(cost/latency trade-off), or whether the channel's signed-state mechanism
subsumes them.

## 5. Message format and signing

Every PSI flight carries a header, and the signature covers header and body:

```
header = gameId || LE64(turn) || LE32(level) || dir || msgType
         || C_self(t) || C_peer(t) || LE32(bodyLength)
msgType: 0 tags, 1 blinded points, 2 transformed points
signature = Sign(sk_P, header || body)
```

Bodies are the existing serialized forms (`serializeBobTagMessage`,
`serializeAliceBlindedMessage`, `serializeBobTransformedMessage`).
Both directions of a turn's query share flights: one message may carry
`(my tags, my blinded points)` together. **TBD:** signature scheme follows the
channel framework (Xaya channels use the chain's key scheme); binary vs current
line-based serialization inside signed bodies (binary preferred before
freezing, since the format becomes evidence).

## 6. Padding

Every set at every level is padded to a fixed size `N_max(lvl)` with dummy
elements from a domain-separated namespace:

```
dummy_i = "D:" || hex(BLAKE3-derive_key("PSI-dummy-v1",
                       subseed(t, lvl, dir, 2) || LE32(i)))[0:16]
```

Dummies can never collide with real cell namespaces (`L<size>:x y`) and never
intersect (each party's dummies are derived from their own secret seed, so a
cross-match has negligible probability). The auditor recomputes the dummies and
verifies both that they are present and that they are exactly the ones the seed
dictates. `N_max` per level is a game parameter. **TBD:** values of `N_max`
(bounds wire size and compute per turn; from `psi_bench`, 1,000 elements per
side costs ~50 ms threaded, which suggests generous headroom is affordable).

## 7. Audit algorithm

Inputs: the signed transcript for disputed turn `t`, and the accused's opening
`(S_P(t), seed_P(t))`, verified against the turn commitment `C_P(t)`
(section 4). No proof of derivation from `k_P` is required: the per-turn
commitment binds the seed, and a seed that fails to reproduce the transcript
is fraud regardless of where it came from.

Steps:

1. Verify every transcript signature and header field (turn, level, direction,
   commitment references).
2. Verify `C_P(t)` opens to `canonical(S_P(t))` with the derived salt.
3. Verify `S_P(t)` is physics-legal given the adjacent turns' opened states
   (game-rule predicate, outside this spec).
4. Recompute, per level and direction, exactly what `P` should have sent:
   pad `S_P(t)` restricted to that level (cascade filtering included), derive
   scalars from the opened seed, produce tags / blinded points / transformed
   points using the existing protocol functions in derivation mode.
5. Byte-compare against the transcript. First mismatch => verdict FRAUD with
   `(turn, level, dir, msgType, byteOffset)`. All match => verdict HONEST for
   this turn.

Soundness rests on the unknown-discrete-log hash-to-group: a party who sent a
blinded point for probe cell `y` cannot exhibit randomness making it match true
cell `x` (that requires `log_{H(x)} H(y)`). Under the pre-2026 `H(x)*G`
construction this audit was forgeable with one modular division; see
`docs/dispute_resolution_notes.md`.

Bob's transformed-points flight (phase 3) deserves a note: it is a function of
the *peer's* blinded points plus Bob's own scalar, both of which the auditor
has (transcript + opening), so it is recomputable without the peer opening
anything.

## 8. On-chain dispute flow

1. **Challenge**: challenger posts the disputed turn's signed messages and a
   challenge deposit.
2. **Open**: accused posts the turn opening within the timeout; silence
   forfeits.
3. **Verify**: on Xaya (both profiles), the audit runs directly: the GSP is
   full computation executed by every node, not gas-metered, and the audit is
   deterministic and cheap (a few thousand scalar multiplications, milliseconds
   at the `N_max` sizes under consideration), so it slots into the game's
   state-transition validity predicate as-is. No verification game is needed.
   Verifiable-VM (Cartesi) or interactive-bisection (Truebit) execution only
   becomes relevant if this spec is ever deployed on a gas-metered chain.
4. **Resolve**: fraud slashes the accused's bond to the challenger; an honest
   verdict forfeits the challenge deposit to the accused. Mid-protocol aborts
   are timeouts, handled by the channel framework (channelized profile) or by
   move deadlines in the game rules (GSP-arbitrated profile).

Disclosure note: in the GSP-arbitrated profile, dispute evidence (the signed
transcript and the disputed turn's opening) becomes public on-chain. Note that
on a small cell universe, revealing a turn's blinding scalars is equivalent to
revealing that turn's positions: given `r` and the transcript's `r * H(x)`,
anyone can test every candidate cell and recover `x`. The per-turn seed
binding (section 4) confines this to exactly the disputed turn, and a proven
dispute typically ends the game, so this is accepted rather than mitigated.

## 9. Implementation plan (in this repo, chain-free first)

1. **Derivation mode**: `DeterministicRng` seeded per section 3, threaded
   through the protocol entry points as an alternative to `randombytes_buf`
   (opt-in parameter, default remains system randomness). The audit and the
   live protocol then share one code path.
2. **Transcript container**: append-only file of `(header, body, signature)`
   records; signing pluggable (dev mode: Ed25519 via libsodium).
3. **`psi_audit` CLI**: takes a transcript file plus an opening file, runs
   section 7, prints the verdict and first-mismatch pointer. Test suite
   includes a honest game, a probe-input forgery (must be caught), and a
   tampered-transcript case (signature failure).
4. **Padding + commitment helpers** shared by live protocol and auditor.
5. Channel/chain integration lives outside this repo (xayaroguelike), consuming
   1-4 as a library.

## 10. Open questions

- ~~Turn-selective seed opening~~ Resolved: `H(seed_P(t))` is bound into the
  per-turn commitment (section 4), so an opening exposes exactly one turn.
- Does the mesh cascade's per-level filtering belong inside the committed
  input (commit per level) or derived from the finest-level commitment at
  audit time (current assumption: derived, since filtering is deterministic
  given both parties' coarse intersections, which are themselves auditable)?
- Bond and deposit sizing relative to the value of leaked information.
- Whether the secretbox mode needs audit support at all, or the spec freezes
  tag mode only (current assumption: tag mode only).
