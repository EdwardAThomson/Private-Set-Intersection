#include "random_utils.h"

#include "blake3_utils.h"

std::vector<std::array<unsigned char, 32>> deriveRandomValues(
    std::size_t count,
    const std::array<unsigned char, 32>& seed) {
    std::vector<std::array<unsigned char, 32>> values;
    values.reserve(count);

    std::array<unsigned char, 32> current = seed;
    for (std::size_t i = 0; i < count; ++i) {
        current = blake3Hash(current);
        values.push_back(current);
    }

    return values;
}
