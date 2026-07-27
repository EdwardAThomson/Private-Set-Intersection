# Dispute Resolution: Design Notes

_Status: design notes, not yet implemented · written 2026-07-27_

Working notes for the blockchain-enabled dispute-resolution protocol tracked in the
ROADMAP backlog. The goal: make every byte of the PSI transcript a deterministic,
signed consequence of committed state, so "did you cheat?" reduces to recomputation,
and recomputation happens on-chain only when someone disputes.

## Layered provenance

Three layers, from three sources:

1. **Commit-and-replay architecture** (2020, ["Preventing cheaters in Fog Of War
   Games"](https://edward-thomson.medium.com/preventing-cheaters-in-fog-of-war-games-69f202fbe107)):
   initial positions hashed on-chain at game start, full action log revealed at game
   end, deterministic game physics so the true position history can be replayed and
   verified, adjudication via Xaya game channels / GSPs. This verifies the *game
   state*: a cheater cannot claim positions that violate physics or edit their
   history.
2. **PSI-transcript binding** (2026 security review by the
   [xaya/fog-of-war](https://github.com/xaya/fog-of-war) authors, who also reported
   issues #1 and #2): extend the same commit-and-derive discipline to the protocol
   randomness, so the PSI messages themselves become auditable against the verified
   position history. Their formulation: commit to input set + PRNG seed before the
   exchange, derive every blinding scalar deterministically from the committed seed,
   sign all messages, audit by recomputing every byte.
3. **Verification-game machinery** (Truebit, Cartesi, Xaya channel disputes): when a
   recomputation is too heavy for on-chain execution, resolve it by interactive
   bisection or a verifiable VM, with bonds slashed on proven fraud.

## The gap layer 2 closes

Layer 1 alone verifies positions but not protocol messages. A cheater can play
physics-perfect game state (replay passes) while the blinded points they send in the
PSI exchange encode probe cells instead of their true cells. The replay cannot detect
this because a blinded point `r * H(x)` reveals nothing about `x` without `r`, and `r`
is secret randomness the audit never sees. Physics checking constrains what a player
*was*; it cannot constrain what their PSI messages *said*.

## Why the audit is sound now (and was not before the hash-to-group fix)

The minimal extension of the 2020 scheme is: at game end, players also reveal their
PSI randomness (blinding scalars `r_i`, per-exchange private scalars `b`). The auditor
checks the signed transcript against the verified positions: does `r_i * H(x_i)` equal
the blinded point actually sent for true cell `x_i`? Do the tags equal
`tag(H2(b * H(y_j)))` for true cells `y_j`?

With the current ristretto255 `hashToGroup` (unknown discrete logs), a cheater who
probed with cell `y` instead of true cell `x` cannot fabricate a scalar `r'` such that
`r' * H(x) = r * H(y)`: computing it requires the discrete log of `H(y)` to base
`H(x)`, which nobody knows. The audit is binding.

Under the pre-fix `H(x) * G` construction this audit was forgeable: discrete logs were
public (`H(x) = h_x * G` with `h_x` computable by anyone), so the cheater could pass
the check with `r' = r * h_y / h_x`, one modular division. The issue #1 fix is
therefore also the enabling condition for transcript auditing; no audit layer could
have compensated for the broken hash-to-group (that attack was passive and left no
dishonest message to audit).

## Two implementations of the binding

- **Reveal-randomness-at-end** (minimal): players store their scalars and reveal them
  at game end alongside positions. Binding, per the argument above, but relies on
  players retaining randomness, and the audit is interactive per value.
- **Seed derivation** (the review's formulation, preferred): all randomness is derived
  from a per-turn seed `seed_P^t = PRF(k_P, t)` with `H(k_P)` committed at game start
  (the BLAKE3 `deriveRandomValues` chain already has the right shape). One opening
  reveals a turn's entire randomness; the audit recomputes every byte either party
  should have sent, non-interactively, and any mismatch against the signed transcript
  is proven fraud. Only disputed turns need opening (PRF/Merkle path), not the whole
  game.

## Sketch of the full flow

- **Setup (on-chain)**: both players bond stake; publish `H(k_P)` and initial state
  commitment; channel rules fix physics and timeouts.
- **Per turn (off-chain)**: exchange signed state commitments, then the PSI flights
  (tag mode, mesh cascade), each message header `(gameId, turn, level, direction,
  C_self, C_peer)` under the signature. Both directions of the fog-of-war query can
  share the same three flights.
- **Dispute (on-chain)**: challenger posts signed messages; accused opens the turn's
  state and seed; verifier recomputes (verifiable VM or bisection) and checks both
  transcript honesty and physics legality; fraud slashes the bond, frivolous
  challenges cost a deposit.
- **Padding**: sets padded to fixed size with dummies derived from the seed in a
  domain-separated namespace (`D:<i>`, never colliding with cell namespaces), so
  cardinality stops leaking and dummies are themselves auditable.

## Limits (write these down wherever this ships)

- Deterrence, not prevention: a prober learns answers before being slashed; bonds must
  exceed the value of the stolen information.
- Aborting after learning your half is handled by channel timeouts (forfeit).
- Out-of-band collusion, or a player merely *acting* on information they should not
  have, is outside the cryptography.

## First implementation artifact

Before any contract work: a deterministic-derivation mode for the protocol (seed in,
all scalars out) behind an explicit opt-in, plus an offline audit CLI that takes a
signed transcript and opened values and reports "honest" or "fraud at byte N". That
makes the whole design testable end to end without touching a chain.
