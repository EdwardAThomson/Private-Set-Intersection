#include "crypto_utils.h"

#include <cstring>
#include <stdexcept>

#include "blake3_utils.h"

namespace {
constexpr char kMembershipTagContext[] = "PSI-membership-tag-v1";
}

RistrettoPoint hashToGroup(const std::string& message) {
    unsigned char fullHash[crypto_hash_sha512_BYTES];
    const unsigned char* input = reinterpret_cast<const unsigned char*>(message.data());
    if (crypto_hash_sha512(fullHash, input, message.size()) != 0) {
        throw std::runtime_error("libsodium SHA-512 hashing failed");
    }

    RistrettoPoint point{};
    if (crypto_core_ristretto255_from_hash(point.data(), fullHash) != 0) {
        sodium_memzero(fullHash, sizeof fullHash);
        throw std::runtime_error("ristretto255 from_hash failed");
    }

    sodium_memzero(fullHash, sizeof fullHash);
    return point;
}

RistrettoPoint HashToGroupCache::get(const std::string& message) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = points_.find(message);
        if (it != points_.end()) {
            return it->second;
        }
    }

    // Compute outside the lock; hashToGroup is deterministic, so a concurrent
    // duplicate computation produces the same point and either insert wins.
    const auto point = hashToGroup(message);

    std::lock_guard<std::mutex> lock(mutex_);
    points_.emplace(message, point);
    return point;
}

RistrettoPoint hashToGroupCached(const std::string& message, HashToGroupCache* cache) {
    return cache != nullptr ? cache->get(message) : hashToGroup(message);
}

std::array<unsigned char, 32> hashPointToKey(const RistrettoPoint& point) {
    unsigned char fullHash[crypto_hash_sha512_BYTES];
    if (crypto_hash_sha512(fullHash, point.data(), point.size()) != 0) {
        throw std::runtime_error("libsodium SHA-512 hashing failed");
    }

    std::array<unsigned char, 32> key{};
    std::memcpy(key.data(), fullHash, key.size());
    sodium_memzero(fullHash, sizeof fullHash);
    return key;
}

MembershipTag keyToMembershipTag(const std::array<unsigned char, 32>& key) {
    return blake3DeriveKey(kMembershipTagContext, key);
}
