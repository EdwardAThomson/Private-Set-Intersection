#include "psi_protocol.h"

#include <cstring>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include "crypto_utils.h"
#include "position_utils.h"
#include "random_utils.h"
#include "serialization_utils.h"

extern "C" {
#include <sodium.h>
}

namespace {

// Reduces a 32-byte derived value to a canonical non-zero ristretto255 scalar.
RistrettoScalar scalarFromDerived(const std::array<unsigned char, 32>& input) {
    unsigned char wide[64] = {0};
    std::memcpy(wide, input.data(), input.size());

    RistrettoScalar scalar{};
    crypto_core_ristretto255_scalar_reduce(scalar.data(), wide);
    sodium_memzero(wide, sizeof wide);

    if (sodium_is_zero(scalar.data(), scalar.size())) {
        scalar[0] = 1;
    }
    return scalar;
}

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
void aliceBlindPositions(AliceResponseMessage& response) {
    std::array<unsigned char, 32> aliceSeed{};
    randombytes_buf(aliceSeed.data(), aliceSeed.size());
    const auto derivedValues = deriveRandomValues(response.state.flooredPositions.size(), aliceSeed);

    response.state.randomScalars.reserve(derivedValues.size());
    response.values.reserve(response.state.flooredPositions.size());

    for (std::size_t i = 0; i < response.state.flooredPositions.size(); ++i) {
        const auto scalar = scalarFromDerived(derivedValues[i]);
        response.state.randomScalars.push_back(scalar);

        const auto hashedPoint = hashToGroup(response.state.flooredPositions[i]);
        const auto blinded = scalarMultiply(scalar, hashedPoint.data(), "Alice's blinding");

        response.values.push_back({std::vector<unsigned char>(blinded.begin(), blinded.end())});
    }

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

BobInitialMessage bobCreateInitialMessage(const std::vector<Unit>& bobUnits) {
    BobInitialMessage message;
    message.state.privateScalar = randomScalar();

    const auto bobPositions = convertToFlooredStrings(bobUnits);
    message.units.reserve(bobPositions.size());

    for (const auto& position : bobPositions) {
        const auto hashedPoint = hashToGroup(position);
        const auto sharedPoint =
            scalarMultiply(message.state.privateScalar, hashedPoint.data(), "Bob's encryption");

        const auto symmetricKey = hashPointToKey(sharedPoint);
        message.units.push_back({secretboxEncrypt(symmetricKey, position)});
    }

    message.serialized = serializeBobEncryptedMessage(message.units);
    return message;
}

AliceResponseMessage aliceProcessBobMessage(const std::string& serializedBobMessage,
                                            const std::vector<Unit>& aliceUnits) {
    AliceResponseMessage response;
    response.state.bobEncryptedUnits = deserializeBobEncryptedMessage(serializedBobMessage);
    response.state.flooredPositions = convertToFlooredStrings(aliceUnits);
    aliceBlindPositions(response);
    return response;
}

BobResponseMessage bobProcessAliceMessage(const std::string& serializedAliceMessage,
                                          const BobSessionState& bobState) {
    const auto aliceValues = deserializeAliceBlindedMessage(serializedAliceMessage);
    BobResponseMessage response;
    response.values.reserve(aliceValues.size());

    for (const auto& value : aliceValues) {
        const auto point = decodeWirePoint(value.blindedPointEncoded, "Alice's blinded message");
        const auto transformed = scalarMultiply(bobState.privateScalar, point.data(), "Bob's response");
        response.values.push_back({std::vector<unsigned char>(transformed.begin(), transformed.end())});
    }

    response.serialized = serializeBobTransformedMessage(response.values);
    return response;
}

std::vector<MatchedUnit> aliceFinalizeIntersection(const std::string& serializedBobResponse,
                                                     const AliceSessionState& aliceState) {
    const auto transformedValues = deserializeBobTransformedMessage(serializedBobResponse);

    std::vector<MatchedUnit> results;
    results.reserve(transformedValues.size());
    std::unordered_set<std::string> usedKeys;
    usedKeys.reserve(transformedValues.size());

    for (std::size_t i = 0; i < transformedValues.size(); ++i) {
        if (i >= aliceState.randomScalars.size()) {
            break;
        }

        const auto sharedPoint = aliceUnblind(transformedValues[i], aliceState.randomScalars[i]);
        const auto key = hashPointToKey(sharedPoint);
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
                                          const std::vector<Unit>& aliceUnits) {
    auto bobMessage = bobCreateInitialMessage(bobUnits);
    auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits);
    auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
    return aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state);
}

BobInitialTagMessage bobCreateInitialTagMessage(const std::vector<Unit>& bobUnits) {
    BobInitialTagMessage message;
    message.state.privateScalar = randomScalar();

    const auto bobPositions = convertToFlooredStrings(bobUnits);
    message.tags.reserve(bobPositions.size());

    for (const auto& position : bobPositions) {
        const auto hashedPoint = hashToGroup(position);
        const auto sharedPoint =
            scalarMultiply(message.state.privateScalar, hashedPoint.data(), "Bob's tagging");

        message.tags.push_back(keyToMembershipTag(hashPointToKey(sharedPoint)));
    }

    message.serialized = serializeBobTagMessage(message.tags);
    return message;
}

AliceResponseMessage aliceProcessBobTagMessage(const std::string& serializedBobTagMessage,
                                               const std::vector<Unit>& aliceUnits) {
    AliceResponseMessage response;
    response.state.bobTags = deserializeBobTagMessage(serializedBobTagMessage);
    response.state.flooredPositions = convertToFlooredStrings(aliceUnits);
    aliceBlindPositions(response);
    return response;
}

std::vector<MatchedUnit> aliceFinalizeIntersectionTags(const std::string& serializedBobResponse,
                                                         const AliceSessionState& aliceState) {
    const auto transformedValues = deserializeBobTransformedMessage(serializedBobResponse);

    std::unordered_set<std::string> bobTagSet;
    bobTagSet.reserve(aliceState.bobTags.size());
    for (const auto& tag : aliceState.bobTags) {
        bobTagSet.emplace(reinterpret_cast<const char*>(tag.data()), tag.size());
    }

    std::vector<MatchedUnit> results;
    std::unordered_set<std::string> matchedTags;

    for (std::size_t i = 0; i < transformedValues.size(); ++i) {
        if (i >= aliceState.randomScalars.size() || i >= aliceState.flooredPositions.size()) {
            break;
        }

        const auto sharedPoint = aliceUnblind(transformedValues[i], aliceState.randomScalars[i]);
        const auto key = hashPointToKey(sharedPoint);
        const auto tag = keyToMembershipTag(key);
        const std::string tagString(reinterpret_cast<const char*>(tag.data()), tag.size());

        // A tag match means Bob derived the same key for this element, which
        // only happens when the element is in his set too. Alice already knows
        // the element: it is her own input at this index.
        if (bobTagSet.find(tagString) != bobTagSet.end() &&
            matchedTags.insert(tagString).second) {
            results.push_back({aliceState.flooredPositions[i], key});
        }
    }

    return results;
}

std::vector<MatchedUnit> runPSIProtocolTags(const std::vector<Unit>& bobUnits,
                                              const std::vector<Unit>& aliceUnits) {
    auto bobMessage = bobCreateInitialTagMessage(bobUnits);
    auto aliceMessage = aliceProcessBobTagMessage(bobMessage.serialized, aliceUnits);
    auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
    return aliceFinalizeIntersectionTags(bobResponse.serialized, aliceMessage.state);
}
