#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <array>
#include <mutex>
#include <string>
#include <unordered_map>

extern "C" {
#include <sodium.h>
}

using RistrettoPoint = std::array<unsigned char, crypto_core_ristretto255_BYTES>;
using RistrettoScalar = std::array<unsigned char, crypto_core_ristretto255_SCALARBYTES>;

// Maps a message to a ristretto255 group element with UNKNOWN discrete log
// (SHA-512 then crypto_core_ristretto255_from_hash, i.e. Elligator 2).
//
// SECURITY: this must never be "simplified" back to hashing to a scalar h and
// returning h*G. With a known discrete log, Alice can unblind one transformed
// value to recover Bob's public key b*G and then derive Bob's symmetric key for
// ANY candidate element offline, enumerating his entire set from a single
// transcript. See docs/security_hardening.md, issue 2.
RistrettoPoint hashToGroup(const std::string& message);

// H2: derives a 32-byte symmetric key from a group element.
std::array<unsigned char, 32> hashPointToKey(const RistrettoPoint& point);

// Local cache of hashToGroup outputs (element string -> group element).
//
// SECURITY: caching here is safe ONLY because it is purely local state that
// never crosses a trust boundary. hashToGroup(x) is deterministic and its
// output never appears on the wire directly: every protocol use multiplies it
// by a fresh per-exchange scalar first (Bob's private scalar or Alice's
// per-run blinding scalars), so the transcript stays fresh even when the
// cached point is reused. Reusing the cache across exchanges therefore leaks
// nothing to the counterparty.
//
// Do NOT extend this idea to wire-visible values (membership tags,
// transformed points) or to Bob's private scalar. With a reused scalar, tags
// become deterministic per element across runs: the counterparty learns how
// many elements changed between runs, and once an element has been in the
// intersection its tag-to-element mapping is known forever, so its
// reappearance is detectable without current visibility. That breaks fog of
// war. Bob's scalar MUST be fresh per exchange; only this local
// element-to-point map may persist.
//
// Thread-safe: lookups and inserts are serialised by an internal mutex so the
// cache can be shared by the parallel per-element loops. On a concurrent miss
// the point may be computed twice, but hashToGroup is deterministic, so both
// computations agree and either insert wins harmlessly.
class HashToGroupCache {
public:
    RistrettoPoint get(const std::string& message);

private:
    std::mutex mutex_;
    std::unordered_map<std::string, RistrettoPoint> points_;
};

// Convenience wrapper: uses the cache when non-null, plain hashToGroup
// otherwise. Byte-identical output either way.
RistrettoPoint hashToGroupCached(const std::string& message, HashToGroupCache* cache);

using MembershipTag = std::array<unsigned char, 32>;

// Tag-mode alternative to encrypting Bob's elements: a one-way,
// domain-separated hash of the per-element symmetric key. Domain separation
// (BLAKE3 derive_key mode with a fixed context string, vs SHA-512 in
// hashPointToKey) keeps tags unrelated to the keys they are derived from.
MembershipTag keyToMembershipTag(const std::array<unsigned char, 32>& key);

#endif // CRYPTO_UTILS_H
