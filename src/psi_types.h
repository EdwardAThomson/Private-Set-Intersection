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

// Wire messages carry only blinded points and membership tags (or, in
// secretbox mode, authenticated ciphertexts). They must never include the
// element itself; both parties' sets would otherwise be readable from the
// transcript (docs/security_hardening.md, issue 1).

struct EncryptedUnit {
    SecretBoxCiphertext ciphertext;
};

struct AliceSentValue {
    std::vector<unsigned char> blindedPointEncoded;
};

struct BobTransformedValue {
    std::vector<unsigned char> transformedPointEncoded;
};

// One element of the computed intersection, with the key both parties derived
// for it. In tag mode the element is Alice's own matching input; in secretbox
// mode it is the decrypted (identical) value from Bob's ciphertext.
struct MatchedUnit {
    std::string element;
    std::array<unsigned char, crypto_secretbox_KEYBYTES> symmetricKey;
};

#endif // PSI_TYPES_H
