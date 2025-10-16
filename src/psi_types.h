#ifndef PSI_TYPES_H
#define PSI_TYPES_H

#include <array>
#include <string>
#include <vector>

#include "chacha_utils.h"

struct Unit {
    std::string id;
    double x;
    double y;
};

struct EncryptedUnit {
    std::string flooredPosition;
    ChaChaCiphertext ciphertext;
};

struct AliceSentValue {
    std::string flooredPosition;
    std::vector<unsigned char> blindedPointEncoded;
};

struct BobTransformedValue {
    std::string flooredPosition;
    std::vector<unsigned char> transformedPointEncoded;
};

struct DecryptedUnit {
    std::string flooredPosition;
    std::string plaintext;
    std::array<unsigned char, crypto_secretbox_KEYBYTES> symmetricKey;
};

#endif // PSI_TYPES_H
