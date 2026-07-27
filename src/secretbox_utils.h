#ifndef SECRETBOX_UTILS_H
#define SECRETBOX_UTILS_H

#include <array>
#include <optional>
#include <string>
#include <vector>

extern "C" {
#include <sodium.h>
}

struct SecretBoxCiphertext {
    std::vector<unsigned char> ciphertext;
    std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce;
};

SecretBoxCiphertext secretboxEncrypt(const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key,
                               const std::string& plaintext);

std::optional<std::string> secretboxDecrypt(
    const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key,
    const SecretBoxCiphertext& payload);

#endif // SECRETBOX_UTILS_H
