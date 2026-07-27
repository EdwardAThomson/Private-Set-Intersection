#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <array>
#include <string>

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

using MembershipTag = std::array<unsigned char, 32>;

// Tag-mode alternative to encrypting Bob's elements: a one-way,
// domain-separated hash of the per-element symmetric key. Domain separation
// (BLAKE3 with a fixed context prefix, vs SHA-512 in hashPointToKey) keeps
// tags unrelated to the keys they are derived from.
MembershipTag keyToMembershipTag(const std::array<unsigned char, 32>& key);

#endif // CRYPTO_UTILS_H
