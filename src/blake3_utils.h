#ifndef BLAKE3_UTILS_H
#define BLAKE3_UTILS_H

#include <array>
#include <cstddef>
#include <string>
#include <vector>

// Returns the 32-byte BLAKE3 hash of an arbitrary byte buffer.
std::array<unsigned char, 32> blake3Hash(const unsigned char* data, std::size_t size);

// Convenience overload for std::vector<uint8_t>.
std::array<unsigned char, 32> blake3Hash(const std::vector<unsigned char>& data);

// Convenience overload for std::string.
std::array<unsigned char, 32> blake3Hash(const std::string& data);

// Convenience overload for fixed-size arrays.
std::array<unsigned char, 32> blake3Hash(const std::array<unsigned char, 32>& data);

#endif // BLAKE3_UTILS_H
