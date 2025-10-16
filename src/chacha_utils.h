#ifndef CHACHA_UTILS_H
#define CHACHA_UTILS_H

#include <array>
#include <optional>
#include <string>
#include <vector>

extern "C" {
#include <sodium.h>
}

struct ChaChaCiphertext {
    std::vector<unsigned char> ciphertext;
    std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce;
};

ChaChaCiphertext chachaEncrypt(const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key,
                               const std::string& plaintext);

std::optional<std::string> chachaDecrypt(
    const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key,
    const ChaChaCiphertext& payload);

#endif // CHACHA_UTILS_H
