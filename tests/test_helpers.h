#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <memory>
#include <stdexcept>
#include <vector>

extern "C" {
#include <sodium.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
}

inline void ensureSodiumInit() {
    static const bool initialised = []() {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialisation failed");
        }
        return true;
    }();
    (void)initialised;
}

struct ECEnvironment {
    ECEnvironment() {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group) {
            throw std::runtime_error("Failed to create EC_GROUP");
        }
        ctx = BN_CTX_new();
        if (!ctx) {
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to create BN_CTX");
        }
    }

    ~ECEnvironment() {
        if (group) {
            EC_GROUP_free(group);
        }
        if (ctx) {
            BN_CTX_free(ctx);
        }
    }

    EC_GROUP* group{nullptr};
    BN_CTX* ctx{nullptr};
};

struct ECPointDeleter {
    void operator()(EC_POINT* point) const {
        if (point) {
            EC_POINT_free(point);
        }
    }
};

using ECPointPtr = std::unique_ptr<EC_POINT, ECPointDeleter>;

inline ECPointPtr makePoint(const EC_GROUP* group) {
    ECPointPtr point(EC_POINT_new(group));
    if (!point) {
        throw std::runtime_error("Failed to allocate EC_POINT");
    }
    return point;
}

inline std::vector<unsigned char> encodePoint(EC_GROUP* group, const EC_POINT* point, BN_CTX* ctx) {
    const std::size_t required =
        EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, ctx);
    if (required == 0) {
        throw std::runtime_error("Failed to determine EC_POINT length");
    }

    std::vector<unsigned char> buffer(required);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buffer.data(), buffer.size(), ctx) !=
        static_cast<int>(required)) {
        throw std::runtime_error("Failed to encode EC_POINT");
    }

    return buffer;
}

#endif // TEST_HELPERS_H
