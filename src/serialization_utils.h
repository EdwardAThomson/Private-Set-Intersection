#ifndef SERIALIZATION_UTILS_H
#define SERIALIZATION_UTILS_H

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>
#include <vector>

#include "psi_types.h"

std::string serializeBobEncryptedMessage(const std::vector<EncryptedUnit>& units);
std::vector<EncryptedUnit> deserializeBobEncryptedMessage(const std::string& data);

std::string serializeAliceBlindedMessage(const std::vector<AliceSentValue>& values);
std::vector<AliceSentValue> deserializeAliceBlindedMessage(const std::string& data);

std::string serializeBobTransformedMessage(const std::vector<BobTransformedValue>& values);
std::vector<BobTransformedValue> deserializeBobTransformedMessage(const std::string& data);

std::string base64Encode(const unsigned char* data, std::size_t size);
std::string base64Encode(const std::vector<unsigned char>& data);
template <std::size_t N>
std::string base64Encode(const std::array<unsigned char, N>& data) {
    return base64Encode(data.data(), data.size());
}

std::string serializeBobEncryptedMessageJson(const std::vector<EncryptedUnit>& units);
std::vector<EncryptedUnit> deserializeBobEncryptedMessageJson(const std::string& json);

std::string serializeAliceBlindedMessageJson(const std::vector<AliceSentValue>& values);
std::vector<AliceSentValue> deserializeAliceBlindedMessageJson(const std::string& json);

std::string serializeBobTransformedMessageJson(const std::vector<BobTransformedValue>& values);
std::vector<BobTransformedValue> deserializeBobTransformedMessageJson(const std::string& json);

std::vector<unsigned char> base64DecodeVector(const std::string& encoded);
template <std::size_t N>
std::array<unsigned char, N> base64DecodeArray(const std::string& encoded) {
    auto result = base64DecodeVector(encoded);
    if (result.size() != N) {
        throw std::runtime_error("Decoded array has unexpected size");
    }
    std::array<unsigned char, N> arr{};
    std::copy(result.begin(), result.end(), arr.begin());
    return arr;
}

#endif // SERIALIZATION_UTILS_H
