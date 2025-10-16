#include "chacha_utils.h"

#include <stdexcept>
#include <string>
#include <vector>

ChaChaCiphertext chachaEncrypt(
    const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key,
    const std::string& plaintext) {
    ChaChaCiphertext result;
    randombytes_buf(result.nonce.data(), result.nonce.size());

    result.ciphertext.resize(plaintext.size() + crypto_secretbox_MACBYTES);
    const unsigned char* messageBytes = reinterpret_cast<const unsigned char*>(plaintext.data());
    if (crypto_secretbox_easy(result.ciphertext.data(), messageBytes, plaintext.size(),
                              result.nonce.data(), key.data()) != 0) {
        throw std::runtime_error("crypto_secretbox_easy failed");
    }
    return result;
}

std::optional<std::string> chachaDecrypt(
    const std::array<unsigned char, crypto_secretbox_KEYBYTES>& key,
    const ChaChaCiphertext& payload) {
    if (payload.ciphertext.size() < crypto_secretbox_MACBYTES) {
        return std::nullopt;
    }

    std::vector<unsigned char> decrypted(payload.ciphertext.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(decrypted.data(), payload.ciphertext.data(),
                                   payload.ciphertext.size(), payload.nonce.data(),
                                   key.data()) != 0) {
        return std::nullopt;
    }

    return std::string(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
}
