#include "psi_protocol.h"

#include <algorithm>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <utility>

#include "crypto_utils.h"
#include "derivation.h"
#include "position_utils.h"
#include "random_utils.h"
#include "serialization_utils.h"

extern "C" {
#include <sodium.h>
}

namespace {

// ---------------------------------------------------------------------------
// Thread-parallel per-element execution.
//
// The per-element work in every protocol phase is an independent scalar
// multiplication (plus hashing), so it is embarrassingly parallel. The
// libsodium primitives used inside the loops (crypto_scalarmult_ristretto255,
// crypto_core_ristretto255_*, crypto_hash_sha512) are thread-safe once
// sodium_init has run.
//
// SECURITY invariants preserved by this design:
//   - Randomness generation is NEVER parallelised. Bob's fresh private scalar
//     comes from randomScalar() before the loop, Alice's blinding scalars are
//     derived up front via deriveRandomValues from one randombytes seed, and
//     secretbox nonces (randombytes per element) are generated in a serial
//     stage. The parallel loops are pure deterministic functions of inputs
//     already fixed.
//   - Workers write results by index into pre-sized vectors, so the output
//     (and therefore the wire transcript) is byte-identical to the serial
//     path. Parallelism changes timing only, never message content or order.
constexpr std::size_t kParallelThreshold = 192;  // serial below this: thread
                                                 // spawn overhead dominates
                                                 // for demo/server sizes
constexpr std::size_t kMaxThreads = 16;

// Runs fn(i) for i in [0, count), chunked across worker threads when count is
// large enough. fn must only touch index-i state (or thread-safe state).
// Exceptions thrown by workers are captured and rethrown on the caller.
template <typename Fn>
void parallelForIndex(std::size_t count, Fn&& fn) {
    if (count < kParallelThreshold) {
        for (std::size_t i = 0; i < count; ++i) {
            fn(i);
        }
        return;
    }

    const unsigned hardware = std::thread::hardware_concurrency();
    const std::size_t threadCount =
        std::min({static_cast<std::size_t>(hardware != 0 ? hardware : 4), kMaxThreads, count});
    const std::size_t chunk = (count + threadCount - 1) / threadCount;

    std::vector<std::thread> workers;
    std::vector<std::exception_ptr> errors(threadCount);
    workers.reserve(threadCount);

    for (std::size_t t = 0; t < threadCount; ++t) {
        workers.emplace_back([&, t]() {
            const std::size_t begin = t * chunk;
            const std::size_t end = std::min(begin + chunk, count);
            try {
                for (std::size_t i = begin; i < end; ++i) {
                    fn(i);
                }
            } catch (...) {
                errors[t] = std::current_exception();
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    for (const auto& error : errors) {
        if (error) {
            std::rethrow_exception(error);
        }
    }
}

// scalarFromDerived now lives in derivation.h so the live protocol and the
// dispute auditor share one reduction code path.

RistrettoScalar randomScalar() {
    RistrettoScalar scalar{};
    crypto_core_ristretto255_scalar_random(scalar.data());
    if (sodium_is_zero(scalar.data(), scalar.size())) {
        scalar[0] = 1;
    }
    return scalar;
}

RistrettoPoint scalarMultiply(const RistrettoScalar& scalar,
                              const unsigned char* pointEncoded,
                              const char* context) {
    RistrettoPoint result{};
    if (crypto_scalarmult_ristretto255(result.data(), scalar.data(), pointEncoded) != 0) {
        throw std::runtime_error(std::string("ristretto255 scalar multiplication failed: ") + context);
    }
    return result;
}

RistrettoPoint decodeWirePoint(const std::vector<unsigned char>& encoded, const char* context) {
    if (encoded.size() != crypto_core_ristretto255_BYTES) {
        throw std::runtime_error(std::string("Invalid point length in ") + context);
    }
    RistrettoPoint point{};
    std::memcpy(point.data(), encoded.data(), point.size());
    return point;
}

// Fills Alice's blinding state and outgoing values; shared by both modes.
// Alice's blinding scalars MUST stay fresh per run. With the default
// SystemRng a new random seed is drawn every call; with DeterministicRng the
// seed is subseed(turn, level, dir, 1), which differs per exchange, so
// freshness holds there too (docs/commit_reveal_spec.md, section 3). The hash
// cache is safe because H(x) is only ever sent multiplied by one of those
// fresh scalars.
void aliceBlindPositions(AliceResponseMessage& response,
                         HashToGroupCache* hashCache,
                         ProtocolRng* rng = nullptr) {
    SystemRng systemRng;
    ProtocolRng& randomness = (rng != nullptr) ? *rng : systemRng;
    const std::array<unsigned char, 32> aliceSeed = randomness.aliceBlindingSeed();
    // Serial by design: seed generation and the chained derivation both touch
    // randombytes/sequential state. Only the pure per-element math below is
    // parallelised.
    const auto derivedValues = deriveRandomValues(response.state.flooredPositions.size(), aliceSeed);

    const std::size_t count = response.state.flooredPositions.size();
    response.state.randomScalars.resize(count);
    response.values.resize(count);

    parallelForIndex(count, [&](std::size_t i) {
        const auto scalar = scalarFromDerived(derivedValues[i]);
        response.state.randomScalars[i] = scalar;

        const auto hashedPoint = hashToGroupCached(response.state.flooredPositions[i], hashCache);
        const auto blinded = scalarMultiply(scalar, hashedPoint.data(), "Alice's blinding");

        response.values[i] = {std::vector<unsigned char>(blinded.begin(), blinded.end())};
    });

    response.serialized = serializeAliceBlindedMessage(response.values);
}

// Unblinds one transformed value back to the shared point b * H(x_i).
RistrettoPoint aliceUnblind(const BobTransformedValue& transformed,
                            const RistrettoScalar& randomScalar) {
    RistrettoScalar inverse{};
    if (crypto_core_ristretto255_scalar_invert(inverse.data(), randomScalar.data()) != 0) {
        throw std::runtime_error("Failed to invert Alice's blinding scalar");
    }

    const auto transformedPoint =
        decodeWirePoint(transformed.transformedPointEncoded, "Bob's transformed message");
    return scalarMultiply(inverse, transformedPoint.data(), "Alice's unblinding");
}

}  // namespace

BobInitialMessage bobCreateInitialMessage(const std::vector<Unit>& bobUnits,
                                          HashToGroupCache* hashCache) {
    BobInitialMessage message;
    // SECURITY: Bob's private scalar MUST be fresh for every exchange. Never
    // cache or reuse it (and never cache the tags/ciphertexts derived from
    // it): a reused scalar makes wire values deterministic per element across
    // runs, letting the counterparty diff runs and re-identify previously
    // matched elements. Only the local hashToGroup cache may persist.
    message.state.privateScalar = randomScalar();

    const auto bobPositions = convertToFlooredStrings(bobUnits);
    const std::size_t count = bobPositions.size();

    // Stage 1 (parallel): deterministic per-element key derivation.
    std::vector<std::array<unsigned char, 32>> keys(count);
    parallelForIndex(count, [&](std::size_t i) {
        const auto hashedPoint = hashToGroupCached(bobPositions[i], hashCache);
        const auto sharedPoint =
            scalarMultiply(message.state.privateScalar, hashedPoint.data(), "Bob's encryption");
        keys[i] = hashPointToKey(sharedPoint);
    });

    // Stage 2 (serial): secretbox nonces come from randombytes; keep all
    // per-element randomness generation single-threaded.
    message.units.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        message.units.push_back({secretboxEncrypt(keys[i], bobPositions[i])});
    }

    message.serialized = serializeBobEncryptedMessage(message.units);
    return message;
}

AliceResponseMessage aliceProcessBobMessage(const std::string& serializedBobMessage,
                                            const std::vector<Unit>& aliceUnits,
                                            HashToGroupCache* hashCache) {
    AliceResponseMessage response;
    response.state.bobEncryptedUnits = deserializeBobEncryptedMessage(serializedBobMessage);
    response.state.flooredPositions = convertToFlooredStrings(aliceUnits);
    aliceBlindPositions(response, hashCache);
    return response;
}

BobResponseMessage bobProcessAliceMessage(const std::string& serializedAliceMessage,
                                          const BobSessionState& bobState) {
    const auto aliceValues = deserializeAliceBlindedMessage(serializedAliceMessage);
    BobResponseMessage response;
    response.values.resize(aliceValues.size());

    parallelForIndex(aliceValues.size(), [&](std::size_t i) {
        const auto point = decodeWirePoint(aliceValues[i].blindedPointEncoded, "Alice's blinded message");
        const auto transformed = scalarMultiply(bobState.privateScalar, point.data(), "Bob's response");
        response.values[i] = {std::vector<unsigned char>(transformed.begin(), transformed.end())};
    });

    response.serialized = serializeBobTransformedMessage(response.values);
    return response;
}

std::vector<MatchedUnit> aliceFinalizeIntersection(const std::string& serializedBobResponse,
                                                     const AliceSessionState& aliceState) {
    const auto transformedValues = deserializeBobTransformedMessage(serializedBobResponse);
    const std::size_t count = std::min(transformedValues.size(), aliceState.randomScalars.size());

    // Stage 1 (parallel): unblind and derive each candidate key. Pure math on
    // fixed inputs, independent per index.
    std::vector<std::array<unsigned char, 32>> keys(count);
    parallelForIndex(count, [&](std::size_t i) {
        const auto sharedPoint = aliceUnblind(transformedValues[i], aliceState.randomScalars[i]);
        keys[i] = hashPointToKey(sharedPoint);
    });

    // Stage 2 (serial): matching. The usedKeys dedup set is shared state, so
    // keeping this loop serial guarantees the same results (and result order)
    // as the original single-threaded implementation.
    std::vector<MatchedUnit> results;
    results.reserve(count);
    std::unordered_set<std::string> usedKeys;
    usedKeys.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        const auto& key = keys[i];
        const std::string keyTag(reinterpret_cast<const char*>(key.data()), key.size());
        if (usedKeys.find(keyTag) != usedKeys.end()) {
            continue;
        }

        // The secretbox is authenticated, so a successful open under this key is
        // itself proof of an intersection; no plaintext comparison is needed.
        for (const auto& encrypted : aliceState.bobEncryptedUnits) {
            const auto decrypted = secretboxDecrypt(key, encrypted.ciphertext);
            if (decrypted) {
                usedKeys.insert(keyTag);
                results.push_back({*decrypted, key});
                break;
            }
        }
    }

    return results;
}

std::vector<MatchedUnit> runPSIProtocol(const std::vector<Unit>& bobUnits,
                                          const std::vector<Unit>& aliceUnits,
                                          HashToGroupCache* bobHashCache,
                                          HashToGroupCache* aliceHashCache) {
    auto bobMessage = bobCreateInitialMessage(bobUnits, bobHashCache);
    auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, aliceHashCache);
    auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
    return aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state);
}

BobInitialTagMessage bobCreateInitialTagMessage(const std::vector<Unit>& bobUnits,
                                                HashToGroupCache* hashCache,
                                                ProtocolRng* rng) {
    return bobCreateInitialTagMessageFromElements(convertToFlooredStrings(bobUnits), hashCache, rng);
}

BobInitialTagMessage bobCreateInitialTagMessageFromElements(
    const std::vector<std::string>& elements,
    HashToGroupCache* hashCache,
    ProtocolRng* rng) {
    BobInitialTagMessage message;
    // SECURITY: fresh scalar per exchange, same reasoning as
    // bobCreateInitialMessage. In tag mode this matters even more: with a
    // reused scalar the tags themselves become stable identifiers, so the
    // counterparty can count changed elements between runs and permanently
    // re-identify any element that ever appeared in the intersection. Tags
    // must therefore be fully recomputed every exchange; only the local
    // hashToGroup cache (never wire-visible) may be reused. DeterministicRng
    // preserves freshness because its subseed differs per turn/level/dir.
    SystemRng systemRng;
    ProtocolRng& randomness = (rng != nullptr) ? *rng : systemRng;
    message.state.privateScalar = randomness.bobPrivateScalar();

    const auto& bobPositions = elements;
    const std::size_t count = bobPositions.size();
    message.tags.resize(count);

    parallelForIndex(count, [&](std::size_t i) {
        const auto hashedPoint = hashToGroupCached(bobPositions[i], hashCache);
        const auto sharedPoint =
            scalarMultiply(message.state.privateScalar, hashedPoint.data(), "Bob's tagging");
        message.tags[i] = keyToMembershipTag(hashPointToKey(sharedPoint));
    });

    message.serialized = serializeBobTagMessage(message.tags);
    return message;
}

AliceResponseMessage aliceProcessBobTagMessage(const std::string& serializedBobTagMessage,
                                               const std::vector<Unit>& aliceUnits,
                                               HashToGroupCache* hashCache,
                                               ProtocolRng* rng) {
    return aliceProcessBobTagMessageFromElements(serializedBobTagMessage,
                                                 convertToFlooredStrings(aliceUnits), hashCache,
                                                 rng);
}

AliceResponseMessage aliceProcessBobTagMessageFromElements(
    const std::string& serializedBobTagMessage,
    const std::vector<std::string>& elements,
    HashToGroupCache* hashCache,
    ProtocolRng* rng) {
    AliceResponseMessage response;
    response.state.bobTags = deserializeBobTagMessage(serializedBobTagMessage);
    response.state.flooredPositions = elements;
    aliceBlindPositions(response, hashCache, rng);
    return response;
}

std::vector<MatchedUnit> aliceFinalizeIntersectionTags(const std::string& serializedBobResponse,
                                                         const AliceSessionState& aliceState) {
    const auto transformedValues = deserializeBobTransformedMessage(serializedBobResponse);
    const std::size_t count = std::min({transformedValues.size(),
                                        aliceState.randomScalars.size(),
                                        aliceState.flooredPositions.size()});

    std::unordered_set<std::string> bobTagSet;
    bobTagSet.reserve(aliceState.bobTags.size());
    for (const auto& tag : aliceState.bobTags) {
        bobTagSet.emplace(reinterpret_cast<const char*>(tag.data()), tag.size());
    }

    // Stage 1 (parallel): unblind, derive key and tag per index. Independent
    // pure computation; bobTagSet is not touched here.
    std::vector<std::array<unsigned char, 32>> keys(count);
    std::vector<MembershipTag> tags(count);
    parallelForIndex(count, [&](std::size_t i) {
        const auto sharedPoint = aliceUnblind(transformedValues[i], aliceState.randomScalars[i]);
        keys[i] = hashPointToKey(sharedPoint);
        tags[i] = keyToMembershipTag(keys[i]);
    });

    // Stage 2 (serial): matching. bobTagSet lookups are read-only, but the
    // matchedTags dedup set is shared mutable state, so this stays serial to
    // keep results and their order identical to the single-threaded version.
    std::vector<MatchedUnit> results;
    std::unordered_set<std::string> matchedTags;

    for (std::size_t i = 0; i < count; ++i) {
        const std::string tagString(reinterpret_cast<const char*>(tags[i].data()), tags[i].size());

        // A tag match means Bob derived the same key for this element, which
        // only happens when the element is in his set too. Alice already knows
        // the element: it is her own input at this index.
        if (bobTagSet.find(tagString) != bobTagSet.end() &&
            matchedTags.insert(tagString).second) {
            results.push_back({aliceState.flooredPositions[i], keys[i]});
        }
    }

    return results;
}

std::vector<MatchedUnit> runPSIProtocolTags(const std::vector<Unit>& bobUnits,
                                              const std::vector<Unit>& aliceUnits,
                                              HashToGroupCache* bobHashCache,
                                              HashToGroupCache* aliceHashCache) {
    auto bobMessage = bobCreateInitialTagMessage(bobUnits, bobHashCache);
    auto aliceMessage = aliceProcessBobTagMessage(bobMessage.serialized, aliceUnits, aliceHashCache);
    auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
    return aliceFinalizeIntersectionTags(bobResponse.serialized, aliceMessage.state);
}
