#include "psi_protocol.h"

#include <memory>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include "crypto_utils.h"
#include "position_utils.h"
#include "random_utils.h"
#include "serialization_utils.h"

extern "C" {
#include <openssl/bn.h>
#include <sodium.h>
}

namespace {

struct BignumDeleter {
    void operator()(BIGNUM* bn) const {
        if (bn) {
            BN_clear_free(bn);
        }
    }
};

using BignumPtr = std::unique_ptr<BIGNUM, BignumDeleter>;

struct ECPointDeleter {
    void operator()(EC_POINT* point) const {
        if (point) {
            EC_POINT_free(point);
        }
    }
};

using ECPointPtr = std::unique_ptr<EC_POINT, ECPointDeleter>;

BignumPtr makeOrder(const EC_GROUP* group, BN_CTX* ctx) {
    BignumPtr order(BN_new());
    if (!order) {
        throw std::runtime_error("Failed to allocate BIGNUM for group order");
    }

    if (EC_GROUP_get_order(group, order.get(), ctx) != 1) {
        throw std::runtime_error("Failed to obtain group order");
    }
    return order;
}

BignumPtr scalarFromBytes(const std::array<unsigned char, 32>& bytes,
                          const BIGNUM* order,
                          BN_CTX* ctx) {
    BignumPtr scalar(BN_bin2bn(bytes.data(), bytes.size(), nullptr));
    if (!scalar) {
        throw std::runtime_error("Failed to create scalar BIGNUM");
    }

    if (BN_mod(scalar.get(), scalar.get(), order, ctx) != 1) {
        throw std::runtime_error("Failed to reduce scalar modulo order");
    }

    if (BN_is_zero(scalar.get())) {
        if (BN_one(scalar.get()) != 1) {
            throw std::runtime_error("Failed to adjust zero scalar");
        }
    }

    return scalar;
}

std::array<unsigned char, 32> normaliseScalarBytes(const std::array<unsigned char, 32>& input,
                                                   const BIGNUM* order,
                                                   BN_CTX* ctx) {
    auto scalar = scalarFromBytes(input, order, ctx);

    std::array<unsigned char, 32> output{};
    if (BN_bn2binpad(scalar.get(), output.data(), output.size()) != static_cast<int>(output.size())) {
        throw std::runtime_error("Failed to serialise scalar to bytes");
    }
    return output;
}

std::array<unsigned char, 32> randomScalarBytes(const BIGNUM* order, BN_CTX* ctx) {
    std::array<unsigned char, 32> seed{};
    randombytes_buf(seed.data(), seed.size());
    return normaliseScalarBytes(seed, order, ctx);
}

std::vector<unsigned char> encodePoint(const EC_GROUP* group,
                                       const EC_POINT* point,
                                       BN_CTX* ctx) {
    const std::size_t required = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, ctx);
    if (required == 0) {
        throw std::runtime_error("Failed to determine encoded point size");
    }

    std::vector<unsigned char> buffer(required);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buffer.data(), buffer.size(), ctx) != required) {
        throw std::runtime_error("Failed to encode EC point");
    }

    return buffer;
}

ECPointPtr makePoint(const EC_GROUP* group) {
    ECPointPtr point(EC_POINT_new(group));
    if (!point) {
        throw std::runtime_error("Failed to allocate EC_POINT");
    }
    return point;
}

ECPointPtr decodePoint(const EC_GROUP* group,
                       const std::vector<unsigned char>& encoded,
                       BN_CTX* ctx) {
    auto point = makePoint(group);
    if (EC_POINT_oct2point(group, point.get(), encoded.data(), encoded.size(), ctx) != 1) {
        throw std::runtime_error("Failed to decode EC point");
    }
    return point;
}

BignumPtr invertScalar(const BIGNUM* scalar, const BIGNUM* order, BN_CTX* ctx) {
    BignumPtr inverse(BN_mod_inverse(nullptr, scalar, order, ctx));
    if (!inverse) {
        throw std::runtime_error("Failed to compute scalar inverse");
    }
    return inverse;
}

} // namespace

BobInitialMessage bobCreateInitialMessage(const std::vector<Unit>& bobUnits,
                                          EC_GROUP* group,
                                          BN_CTX* ctx) {
    if (!group || !ctx) {
        throw std::invalid_argument("bobCreateInitialMessage requires valid group and context");
    }

    BobInitialMessage message;
    auto order = makeOrder(group, ctx);

    message.state.privateScalar = randomScalarBytes(order.get(), ctx);
    auto bobPrivate = scalarFromBytes(message.state.privateScalar, order.get(), ctx);

    const auto bobPositions = convertToFlooredStrings(bobUnits);
    message.units.reserve(bobPositions.size());

    for (const auto& position : bobPositions) {
        ECPointPtr h1(hashToGroup(position, group, ctx));
        if (!h1) {
            throw std::runtime_error("hashToGroup returned null point");
        }

        auto ok = makePoint(group);
        if (EC_POINT_mul(group, ok.get(), nullptr, h1.get(), bobPrivate.get(), ctx) != 1) {
            throw std::runtime_error("EC_POINT_mul failed for Bob's encryption");
        }

        const auto symmetricKey = hashPointToKey(ok.get(), group, ctx);
        const auto ciphertext = chachaEncrypt(symmetricKey, position);

        message.units.push_back({position, ciphertext});
    }

    message.serialized = serializeBobEncryptedMessage(message.units);
    return message;
}

AliceResponseMessage aliceProcessBobMessage(const std::string& serializedBobMessage,
                                            const std::vector<Unit>& aliceUnits,
                                            EC_GROUP* group,
                                            BN_CTX* ctx) {
    if (!group || !ctx) {
        throw std::invalid_argument("aliceProcessBobMessage requires valid group and context");
    }

    AliceResponseMessage response;
    response.state.bobEncryptedUnits = deserializeBobEncryptedMessage(serializedBobMessage);
    response.state.flooredPositions = convertToFlooredStrings(aliceUnits);

    auto order = makeOrder(group, ctx);
    std::array<unsigned char, 32> aliceSeed = randomScalarBytes(order.get(), ctx);
    auto derivedValues = deriveRandomValues(response.state.flooredPositions.size(), aliceSeed);
    response.state.randomScalars.reserve(derivedValues.size());
    response.values.reserve(response.state.flooredPositions.size());

    for (std::size_t i = 0; i < response.state.flooredPositions.size(); ++i) {
        const auto normalised = normaliseScalarBytes(derivedValues[i], order.get(), ctx);
        response.state.randomScalars.push_back(normalised);

        auto scalar = scalarFromBytes(normalised, order.get(), ctx);

        ECPointPtr h1(hashToGroup(response.state.flooredPositions[i], group, ctx));
        if (!h1) {
            throw std::runtime_error("hashToGroup returned null point for Alice");
        }

        auto blinded = makePoint(group);
        if (EC_POINT_mul(group, blinded.get(), nullptr, h1.get(), scalar.get(), ctx) != 1) {
            throw std::runtime_error("EC_POINT_mul failed for Alice's blinding");
        }

        auto encoded = encodePoint(group, blinded.get(), ctx);
        response.values.push_back({response.state.flooredPositions[i], std::move(encoded)});
    }

    response.serialized = serializeAliceBlindedMessage(response.values);
    return response;
}

BobResponseMessage bobProcessAliceMessage(const std::string& serializedAliceMessage,
                                          const BobSessionState& bobState,
                                          EC_GROUP* group,
                                          BN_CTX* ctx) {
    if (!group || !ctx) {
        throw std::invalid_argument("bobProcessAliceMessage requires valid group and context");
    }

    auto order = makeOrder(group, ctx);
    auto bobPrivate = scalarFromBytes(bobState.privateScalar, order.get(), ctx);

    const auto aliceValues = deserializeAliceBlindedMessage(serializedAliceMessage);
    BobResponseMessage response;
    response.values.reserve(aliceValues.size());

    for (const auto& value : aliceValues) {
        auto point = decodePoint(group, value.blindedPointEncoded, ctx);
        auto transformed = makePoint(group);
        if (EC_POINT_mul(group, transformed.get(), nullptr, point.get(), bobPrivate.get(), ctx) != 1) {
            throw std::runtime_error("EC_POINT_mul failed for Bob's response");
        }

        auto encoded = encodePoint(group, transformed.get(), ctx);
        response.values.push_back({value.flooredPosition, std::move(encoded)});
    }

    response.serialized = serializeBobTransformedMessage(response.values);
    return response;
}

std::vector<DecryptedUnit> aliceFinalizeIntersection(const std::string& serializedBobResponse,
                                                     const AliceSessionState& aliceState,
                                                     EC_GROUP* group,
                                                     BN_CTX* ctx) {
    if (!group || !ctx) {
        throw std::invalid_argument("aliceFinalizeIntersection requires valid group and context");
    }

    const auto transformedValues = deserializeBobTransformedMessage(serializedBobResponse);
    auto order = makeOrder(group, ctx);

    std::vector<DecryptedUnit> results;
    results.reserve(transformedValues.size());
    std::unordered_set<std::string> usedKeys;
    usedKeys.reserve(transformedValues.size());

    for (std::size_t i = 0; i < transformedValues.size(); ++i) {
        if (i >= aliceState.randomScalars.size()) {
            break;
        }

        auto aliceScalar = scalarFromBytes(aliceState.randomScalars[i], order.get(), ctx);
        auto aliceScalarInverse = invertScalar(aliceScalar.get(), order.get(), ctx);

        auto transformedPoint = decodePoint(group, transformedValues[i].transformedPointEncoded, ctx);
        auto okPoint = makePoint(group);
        if (EC_POINT_mul(group, okPoint.get(), nullptr, transformedPoint.get(), aliceScalarInverse.get(), ctx) != 1) {
            throw std::runtime_error("EC_POINT_mul failed while deriving shared point");
        }

        const auto key = hashPointToKey(okPoint.get(), group, ctx);
        const std::string keyTag(reinterpret_cast<const char*>(key.data()), key.size());
        if (usedKeys.find(keyTag) != usedKeys.end()) {
            continue;
        }

        for (const auto& encrypted : aliceState.bobEncryptedUnits) {
            const auto decrypted = chachaDecrypt(key, encrypted.ciphertext);
            if (decrypted && *decrypted == encrypted.flooredPosition) {
                usedKeys.insert(keyTag);
                results.push_back({encrypted.flooredPosition, *decrypted, key});
                break;
            }
        }
    }

    return results;
}

std::vector<DecryptedUnit> runPSIProtocol(const std::vector<Unit>& bobUnits,
                                          const std::vector<Unit>& aliceUnits,
                                          EC_GROUP* group,
                                          BN_CTX* ctx) {
    auto bobMessage = bobCreateInitialMessage(bobUnits, group, ctx);
    auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, group, ctx);
    auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state, group, ctx);
    return aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state, group, ctx);
}
