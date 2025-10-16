#include "crypto_utils.h"

#include <array>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/obj_mac.h>

extern "C" {
#include <sodium.h>
}

namespace {
constexpr std::size_t kScalarBytes = 32;
constexpr std::size_t kHashBytes = crypto_hash_sha512_BYTES;

std::string bytesToHex(const unsigned char* data, std::size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        unsigned char byte = data[i];
        hex.push_back(kHex[byte >> 4]);
        hex.push_back(kHex[byte & 0x0F]);
    }
    return hex;
}
}

EC_POINT* hashToGroup(const std::string& message, EC_GROUP* group, BN_CTX* ctx) {
    if (!group || !ctx) {
        throw std::invalid_argument("hashToGroup requires non-null group and context");
    }

    unsigned char fullHash[kHashBytes];
    const unsigned char* input =
        reinterpret_cast<const unsigned char*>(message.data());
    if (crypto_hash_sha512(fullHash, input, message.size()) != 0) {
        throw std::runtime_error("libsodium SHA-512 hashing failed");
    }

    // Use the first 32 bytes of SHA-512 output, as in the JS reference.
    unsigned char scalarBytes[kScalarBytes];
    std::memcpy(scalarBytes, fullHash, kScalarBytes);
    sodium_memzero(fullHash, sizeof fullHash);

    BIGNUM* order = BN_new();
    BIGNUM* scalar = BN_bin2bn(scalarBytes, kScalarBytes, nullptr);
    if (!order || !scalar) {
        BN_free(order);
        BN_clear_free(scalar);
        throw std::runtime_error("Failed to allocate BIGNUMs for hashToGroup");
    }

    if (EC_GROUP_get_order(group, order, ctx) != 1) {
        BN_free(order);
        BN_clear_free(scalar);
        throw std::runtime_error("Failed to obtain group order");
    }

    if (BN_mod(scalar, scalar, order, ctx) != 1) {
        BN_free(order);
        BN_clear_free(scalar);
        throw std::runtime_error("Failed to reduce scalar modulo group order");
    }

    if (BN_is_zero(scalar)) {
        if (BN_one(scalar) != 1) {
            BN_free(order);
            BN_clear_free(scalar);
            throw std::runtime_error("Failed to adjust zero scalar");
        }
    }

    EC_POINT* point = EC_POINT_new(group);
    if (!point) {
        BN_free(order);
        BN_clear_free(scalar);
        throw std::runtime_error("Failed to create EC_POINT");
    }

    if (EC_POINT_mul(group, point, scalar, nullptr, nullptr, ctx) != 1) {
        EC_POINT_free(point);
        BN_free(order);
        BN_clear_free(scalar);
        throw std::runtime_error("EC_POINT_mul failed");
    }

    BN_free(order);
    BN_clear_free(scalar);
    sodium_memzero(scalarBytes, sizeof scalarBytes);
    return point;
}

std::array<unsigned char, 32> hashPointToKey(const EC_POINT* point, const EC_GROUP* group, BN_CTX* ctx) {
    if (!point || !group || !ctx) {
        throw std::invalid_argument("hashPointToKey requires non-null point, group, and context");
    }

    const std::size_t octetLen = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, ctx);
    if (octetLen == 0) {
        throw std::runtime_error("Failed to determine EC point octet length");
    }

    std::vector<unsigned char> encoded(octetLen);
    const std::size_t written = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, encoded.data(), encoded.size(), ctx);
    if (written != octetLen) {
        throw std::runtime_error("Failed to encode EC point to octets");
    }

    const std::string hex = bytesToHex(encoded.data(), encoded.size());

    unsigned char fullHash[kHashBytes];
    const unsigned char* utf8 = reinterpret_cast<const unsigned char*>(hex.data());
    if (crypto_hash_sha512(fullHash, utf8, hex.size()) != 0) {
        sodium_memzero(encoded.data(), encoded.size());
        throw std::runtime_error("libsodium SHA-512 hashing failed");
    }

    std::array<unsigned char, 32> key{};
    std::memcpy(key.data(), fullHash, key.size());

    sodium_memzero(fullHash, sizeof fullHash);
    sodium_memzero(encoded.data(), encoded.size());
    return key;
}
