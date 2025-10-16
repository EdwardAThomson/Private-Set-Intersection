#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <array>
#include <cstddef>
#include <vector>

// Derive a sequence of 32-byte values by repeatedly hashing the previous value with BLAKE3.
std::vector<std::array<unsigned char, 32>> deriveRandomValues(
    std::size_t count,
    const std::array<unsigned char, 32>& seed);

#endif // RANDOM_UTILS_H
