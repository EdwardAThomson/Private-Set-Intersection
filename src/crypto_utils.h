#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <array>
#include <openssl/ec.h>
#include <string>

// Function declarations
EC_POINT* hashToGroup(const std::string& message, EC_GROUP* group, BN_CTX* ctx);
std::array<unsigned char, 32> hashPointToKey(const EC_POINT* point, const EC_GROUP* group, BN_CTX* ctx);

#endif // CRYPTO_UTILS_H
