#include "blake3_utils.h"

#include <stdexcept>

extern "C" {
#include "blake3.h"
}

std::array<unsigned char, 32> blake3Hash(const unsigned char* data, std::size_t size) {
    if (data == nullptr && size != 0) {
        throw std::invalid_argument("blake3Hash received null data with non-zero size");
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    if (size > 0) {
        blake3_hasher_update(&hasher, data, size);
    }

    std::array<unsigned char, 32> output{};
    blake3_hasher_finalize(&hasher, output.data(), output.size());
    return output;
}

std::array<unsigned char, 32> blake3Hash(const std::vector<unsigned char>& data) {
    return blake3Hash(data.data(), data.size());
}

std::array<unsigned char, 32> blake3Hash(const std::string& data) {
    return blake3Hash(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

std::array<unsigned char, 32> blake3Hash(const std::array<unsigned char, 32>& data) {
    return blake3Hash(data.data(), data.size());
}

std::array<unsigned char, 32> blake3DeriveKey(const std::string& context,
                                              const unsigned char* material,
                                              std::size_t size) {
    if (material == nullptr && size != 0) {
        throw std::invalid_argument("blake3DeriveKey received null material with non-zero size");
    }

    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, context.c_str());

    if (size > 0) {
        blake3_hasher_update(&hasher, material, size);
    }

    std::array<unsigned char, 32> output{};
    blake3_hasher_finalize(&hasher, output.data(), output.size());
    return output;
}

std::array<unsigned char, 32> blake3DeriveKey(const std::string& context,
                                              const std::array<unsigned char, 32>& material) {
    return blake3DeriveKey(context, material.data(), material.size());
}
