#ifndef PSI_TYPES_H
#define PSI_TYPES_H

#include <array>
#include <string>
#include <vector>

#include "secretbox_utils.h"

struct Unit {
    std::string id;
    double x;
    double y;
};

// Wire messages carry only blinded points and authenticated ciphertexts.
// They must never include the plaintext element; both parties' sets would
// otherwise be readable from the transcript (docs/security_hardening.md, issue 1).

struct EncryptedUnit {
    SecretBoxCiphertext ciphertext;
};

struct AliceSentValue {
    std::vector<unsigned char> blindedPointEncoded;
};

struct BobTransformedValue {
    std::vector<unsigned char> transformedPointEncoded;
};

struct DecryptedUnit {
    std::string plaintext;
    std::array<unsigned char, crypto_secretbox_KEYBYTES> symmetricKey;
};

#endif // PSI_TYPES_H
