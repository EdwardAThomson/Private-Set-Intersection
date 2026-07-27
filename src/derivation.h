#ifndef DERIVATION_H
#define DERIVATION_H

// Deterministic derivation mode for the commit-reveal dispute protocol
// (docs/commit_reveal_spec.md, sections 3, 4 and 6). All protocol randomness
// for a whole game derives from one 32-byte master key per player, so an
// auditor holding a turn's opened seed can recompute every byte that party
// should have sent.
//
// SECURITY: DeterministicRng is OPT-IN for the dispute-audit deployment; the
// default everywhere remains system randomness (SystemRng, randombytes_buf).
// The fresh-scalar-per-exchange invariant documented in psi_protocol.h still
// holds in deterministic mode because the subseed differs per turn, level and
// direction, so no scalar is ever reused across exchanges.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "crypto_utils.h"

// Frozen context strings (spec section 3; the TBD there is resolved by
// freezing exactly these values, changing any of them is a hard fork of the
// audit).
inline constexpr char kTurnSeedContext[] = "PSI-turn-seed-v1";
inline constexpr char kSubseedContext[] = "PSI-subseed-v1";
inline constexpr char kCommitContext[] = "PSI-commit-v1";
inline constexpr char kDummyContext[] = "PSI-dummy-v1";

// seed_P(t) = BLAKE3-derive_key("PSI-turn-seed-v1", k_P || LE64(t)).
std::array<unsigned char, 32> turnSeed(const std::array<unsigned char, 32>& masterKey,
                                       std::uint64_t turn);

// subseed_P(t, lvl, dir, role)
//   = BLAKE3-derive_key("PSI-subseed-v1", seed_P(t) || LE32(lvl) || dir || role).
// dir: 0 = P queries Q, 1 = Q queries P.
// role: 0 = Bob-role scalar, 1 = Alice-role blinding chain, 2 = dummy padding,
//       3 = commitment salt.
std::array<unsigned char, 32> subseed(const std::array<unsigned char, 32>& turnSeedValue,
                                      std::uint32_t level,
                                      std::uint8_t dir,
                                      std::uint8_t role);

// Reduces a 32-byte derived value to a canonical non-zero ristretto255
// scalar. Shared by the live protocol (psi_protocol.cpp) and the auditor so
// both use one code path.
RistrettoScalar scalarFromDerived(const std::array<unsigned char, 32>& input);

// Source of the two random inputs the tag-mode protocol consumes: Bob's
// per-exchange private scalar and Alice's per-exchange blinding-chain seed.
// Passed as an optional parameter through the tag-mode entry points; nullptr
// means SystemRng (current behaviour, existing callers unchanged).
class ProtocolRng {
public:
    virtual ~ProtocolRng() = default;
    virtual RistrettoScalar bobPrivateScalar() = 0;
    virtual std::array<unsigned char, 32> aliceBlindingSeed() = 0;
};

// Default: system randomness, exactly the pre-existing behaviour
// (crypto_core_ristretto255_scalar_random / randombytes_buf).
class SystemRng : public ProtocolRng {
public:
    RistrettoScalar bobPrivateScalar() override;
    std::array<unsigned char, 32> aliceBlindingSeed() override;
};

// Deterministic derivation per spec section 3, seeded with a turn seed plus
// the (level, dir) coordinates of one exchange. One instance covers exactly
// one exchange in one direction; construct a fresh one per (turn, level, dir)
// so the fresh-scalar invariant holds.
class DeterministicRng : public ProtocolRng {
public:
    DeterministicRng(const std::array<unsigned char, 32>& turnSeedValue,
                     std::uint32_t level,
                     std::uint8_t dir);

    // scalarFromDerived(subseed(t, lvl, dir, 0)), non-zero guaranteed.
    RistrettoScalar bobPrivateScalar() override;
    // subseed(t, lvl, dir, 1); the existing deriveRandomValues chain expands
    // it to the per-element blinding scalars.
    std::array<unsigned char, 32> aliceBlindingSeed() override;

private:
    std::array<unsigned char, 32> turnSeed_;
    std::uint32_t level_;
    std::uint8_t dir_;
};

// Dummy padding (spec section 6): pads `elements` to exactly nMax entries by
// appending
//   dummy_i = "D:" || hex(BLAKE3-derive_key("PSI-dummy-v1",
//                          subseedForDummies || LE32(i)))[0:16]
// then returns the whole padded set sorted (the canonical protocol input
// order, so recomputation is byte-reproducible). The "D:" prefix can never
// collide with real cell namespaces ("L<size>:x y"), and each party's dummies
// come from their own secret subseed, so cross-party dummy matches have
// negligible probability. Throws if elements.size() > nMax.
std::vector<std::string> padElements(const std::vector<std::string>& elements,
                                     std::size_t nMax,
                                     const std::array<unsigned char, 32>& subseedForDummies);

// Sorted, newline-joined canonical form of an element set (spec section 4).
std::string canonicalizeElements(const std::vector<std::string>& elements);

// Per-turn commitment (spec section 4):
//   C(t) = H( canonical(S(t)) || H(seed(t)) || subseed(t, 0, 0, 3) )
// where H is BLAKE3 derive_key with context "PSI-commit-v1" (the spec leaves
// H's exact instantiation implicit; derive_key with the commit context is the
// simplest domain-separated choice, applied uniformly to both the inner seed
// hash and the outer commitment).
std::array<unsigned char, 32> computeCommitment(const std::vector<std::string>& canonicalElements,
                                                const std::array<unsigned char, 32>& turnSeedValue);

#endif  // DERIVATION_H
