#include "serialization_utils.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>

extern "C" {
#include <sodium.h>
}

namespace {

void ensureSodiumInitLocal() {
    static const bool initialised = []() {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialisation failed");
        }
        return true;
    }();
    (void)initialised;
}

}  // namespace

std::string base64Encode(const unsigned char* data, std::size_t size) {
    ensureSodiumInitLocal();
    if (size == 0) {
        return {};
    }
    std::string encoded;
    encoded.resize(sodium_base64_encoded_len(size, sodium_base64_VARIANT_URLSAFE_NO_PADDING));
    sodium_bin2base64(encoded.data(), encoded.size(), data, size, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    encoded.resize(std::strlen(encoded.c_str()));
    return encoded;
}

std::string base64Encode(const std::vector<unsigned char>& data) {
    ensureSodiumInitLocal();
    return base64Encode(data.data(), data.size());
}

std::vector<unsigned char> base64DecodeVector(const std::string& encoded) {
    ensureSodiumInitLocal();
    if (encoded.empty()) {
        return {};
    }
    std::vector<unsigned char> decoded(encoded.size());  // upper bound
    std::size_t actualSize = 0;
    if (sodium_base642bin(decoded.data(), decoded.size(), encoded.c_str(), encoded.size(), nullptr, &actualSize, nullptr,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        throw std::runtime_error("Failed to decode base64 data");
    }
    decoded.resize(actualSize);
    return decoded;
}

void expectHeader(std::istringstream& stream, char expected) {
    char header;
    if (!(stream >> header) || header != expected) {
        throw std::runtime_error("Invalid message header");
    }
}

std::size_t readCount(std::istringstream& stream) {
    std::size_t count = 0;
    if (!(stream >> count)) {
        throw std::runtime_error("Invalid message count");
    }
    stream.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return count;
}

std::string readLine(std::istringstream& stream) {
    std::string line;
    if (!std::getline(stream, line)) {
        throw std::runtime_error("Unexpected end of message");
    }
    return line;
}

template <typename Writer>
std::string serializeGeneric(char header, const Writer& writer, std::size_t count) {
    std::ostringstream oss;
    oss << header << " " << count << "\n";
    writer(oss);
    return oss.str();
}

std::string serializeBobEncryptedMessage(const std::vector<EncryptedUnit>& units) {
    ensureSodiumInitLocal();
    auto writer = [&units](std::ostringstream& oss) {
        for (const auto& unit : units) {
            oss << unit.flooredPosition << "\n";
            oss << base64Encode(unit.ciphertext.ciphertext) << "\n";
            oss << base64Encode(unit.ciphertext.nonce) << "\n";
        }
    };
    return serializeGeneric('B', writer, units.size());
}

std::vector<EncryptedUnit> deserializeBobEncryptedMessage(const std::string& data) {
    ensureSodiumInitLocal();
    std::istringstream stream(data);
    expectHeader(stream, 'B');
    const std::size_t count = readCount(stream);
    std::vector<EncryptedUnit> units;
    units.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const std::string position = readLine(stream);
        const std::string ciphertextB64 = readLine(stream);
        const std::string nonceB64 = readLine(stream);

        ChaChaCiphertext payload;
        payload.ciphertext = base64DecodeVector(ciphertextB64);
        auto nonceVec = base64DecodeVector(nonceB64);
        if (nonceVec.size() != crypto_secretbox_NONCEBYTES) {
            throw std::runtime_error("Invalid nonce length in message");
        }
        std::copy(nonceVec.begin(), nonceVec.end(), payload.nonce.begin());
        units.push_back({position, std::move(payload)});
    }
    return units;
}

std::string serializeAliceBlindedMessage(const std::vector<AliceSentValue>& values) {
    ensureSodiumInitLocal();
    auto writer = [&values](std::ostringstream& oss) {
        for (const auto& value : values) {
            oss << value.flooredPosition << "\n";
            oss << base64Encode(value.blindedPointEncoded) << "\n";
        }
    };
    return serializeGeneric('A', writer, values.size());
}

std::vector<AliceSentValue> deserializeAliceBlindedMessage(const std::string& data) {
    ensureSodiumInitLocal();
    std::istringstream stream(data);
    expectHeader(stream, 'A');
    const std::size_t count = readCount(stream);
    std::vector<AliceSentValue> values;
    values.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        AliceSentValue value;
        value.flooredPosition = readLine(stream);
        const std::string encodedPoint = readLine(stream);
        value.blindedPointEncoded = base64DecodeVector(encodedPoint);
        values.push_back(std::move(value));
    }
    return values;
}

std::string serializeBobTransformedMessage(const std::vector<BobTransformedValue>& values) {
    ensureSodiumInitLocal();
    auto writer = [&values](std::ostringstream& oss) {
        for (const auto& value : values) {
            oss << value.flooredPosition << "\n";
            oss << base64Encode(value.transformedPointEncoded) << "\n";
        }
    };
    return serializeGeneric('R', writer, values.size());
}

std::vector<BobTransformedValue> deserializeBobTransformedMessage(const std::string& data) {
    ensureSodiumInitLocal();
    std::istringstream stream(data);
    expectHeader(stream, 'R');
    const std::size_t count = readCount(stream);
    std::vector<BobTransformedValue> values;
    values.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        BobTransformedValue value;
        value.flooredPosition = readLine(stream);
        const std::string encodedPoint = readLine(stream);
        value.transformedPointEncoded = base64DecodeVector(encodedPoint);
        values.push_back(std::move(value));
    }
    return values;
}

namespace {

std::string escapeJson(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (char c : input) {
        switch (c) {
            case '"':
                output += "\\\"";
                break;
            case '\\':
                output += "\\\\";
                break;
            case '\n':
                output += "\\n";
                break;
            case '\r':
                output += "\\r";
                break;
            case '\t':
                output += "\\t";
                break;
            default:
                output += c;
                break;
        }
    }
    return output;
}

std::string trim(const std::string& input) {
    std::size_t start = 0;
    while (start < input.size() && std::isspace(static_cast<unsigned char>(input[start]))) {
        ++start;
    }
    std::size_t end = input.size();
    while (end > start && std::isspace(static_cast<unsigned char>(input[end - 1]))) {
        --end;
    }
    return input.substr(start, end - start);
}

std::vector<std::string> splitJsonObjects(const std::string& inner) {
    std::vector<std::string> objects;
    int depth = 0;
    std::size_t start = std::string::npos;
    for (std::size_t i = 0; i < inner.size(); ++i) {
        char c = inner[i];
        if (c == '{') {
            if (depth == 0) {
                start = i;
            }
            ++depth;
        } else if (c == '}') {
            if (depth == 0) {
                throw std::runtime_error("Unbalanced JSON braces");
            }
            --depth;
            if (depth == 0 && start != std::string::npos) {
                objects.push_back(inner.substr(start, i - start + 1));
                start = std::string::npos;
            }
        }
    }
    if (depth != 0) {
        throw std::runtime_error("Unbalanced JSON braces");
    }
    return objects;
}

std::string extractJsonValue(const std::string& object, const std::string& key) {
    const std::string pattern = "\"" + key + "\":\"";
    auto startPos = object.find(pattern);
    if (startPos == std::string::npos) {
        throw std::runtime_error("Missing key in JSON: " + key);
    }
    std::size_t pos = startPos + pattern.size();
    std::string value;
    while (pos < object.size()) {
        char c = object[pos++];
        if (c == '\\') {
            if (pos >= object.size()) {
                throw std::runtime_error("Invalid escape in JSON string");
            }
            char next = object[pos++];
            switch (next) {
                case '"': value.push_back('"'); break;
                case '\\': value.push_back('\\'); break;
                case 'n': value.push_back('\n'); break;
                case 'r': value.push_back('\r'); break;
                case 't': value.push_back('\t'); break;
                default: value.push_back(next); break;
            }
        } else if (c == '"') {
            return value;
        } else {
            value.push_back(c);
        }
    }
    throw std::runtime_error("Unterminated JSON string value");
}

std::string wrapJsonArray(const std::vector<std::string>& objects) {
    std::ostringstream oss;
    oss << "{\"items\":[";
    for (std::size_t i = 0; i < objects.size(); ++i) {
        if (i > 0) {
            oss << ',';
        }
        oss << objects[i];
    }
    oss << "]}";
    return oss.str();
}

std::vector<std::string> unwrapJsonArray(const std::string& json) {
    auto trimmed = trim(json);
    const std::string prefix = "{\"items\":[";
    const std::string suffix = "]}";
    if (trimmed.rfind(prefix, 0) != 0 || trimmed.size() < prefix.size() + suffix.size()) {
        throw std::runtime_error("Invalid JSON message format");
    }
    auto inner = trimmed.substr(prefix.size(), trimmed.size() - prefix.size() - suffix.size());
    inner = trim(inner);
    if (inner.empty()) {
        return {};
    }
    return splitJsonObjects(inner);
}

}  // namespace

std::string serializeBobEncryptedMessageJson(const std::vector<EncryptedUnit>& units) {
    std::vector<std::string> objects;
    objects.reserve(units.size());
    for (const auto& unit : units) {
        std::ostringstream oss;
        oss << "{\"position\":\"" << escapeJson(unit.flooredPosition)
            << "\",\"ciphertext\":\"" << escapeJson(base64Encode(unit.ciphertext.ciphertext))
            << "\",\"nonce\":\"" << escapeJson(base64Encode(unit.ciphertext.nonce)) << "\"}";
        objects.push_back(oss.str());
    }
    return wrapJsonArray(objects);
}

std::vector<EncryptedUnit> deserializeBobEncryptedMessageJson(const std::string& json) {
    auto objects = unwrapJsonArray(json);
    std::vector<EncryptedUnit> units;
    units.reserve(objects.size());
    for (const auto& obj : objects) {
        EncryptedUnit unit;
        unit.flooredPosition = extractJsonValue(obj, "position");
        auto cipherB64 = extractJsonValue(obj, "ciphertext");
        auto nonceB64 = extractJsonValue(obj, "nonce");
        unit.ciphertext.ciphertext = base64DecodeVector(cipherB64);
        auto nonceVec = base64DecodeVector(nonceB64);
        if (nonceVec.size() != crypto_secretbox_NONCEBYTES) {
            throw std::runtime_error("Invalid nonce length in JSON message");
        }
        std::copy(nonceVec.begin(), nonceVec.end(), unit.ciphertext.nonce.begin());
        units.push_back(std::move(unit));
    }
    return units;
}

std::string serializeAliceBlindedMessageJson(const std::vector<AliceSentValue>& values) {
    std::vector<std::string> objects;
    objects.reserve(values.size());
    for (const auto& value : values) {
        std::ostringstream oss;
        oss << "{\"position\":\"" << escapeJson(value.flooredPosition)
            << "\",\"blindedPoint\":\"" << escapeJson(base64Encode(value.blindedPointEncoded)) << "\"}";
        objects.push_back(oss.str());
    }
    return wrapJsonArray(objects);
}

std::vector<AliceSentValue> deserializeAliceBlindedMessageJson(const std::string& json) {
    auto objects = unwrapJsonArray(json);
    std::vector<AliceSentValue> values;
    values.reserve(objects.size());
    for (const auto& obj : objects) {
        AliceSentValue value;
        value.flooredPosition = extractJsonValue(obj, "position");
        auto encoded = extractJsonValue(obj, "blindedPoint");
        value.blindedPointEncoded = base64DecodeVector(encoded);
        values.push_back(std::move(value));
    }
    return values;
}

std::string serializeBobTransformedMessageJson(const std::vector<BobTransformedValue>& values) {
    std::vector<std::string> objects;
    objects.reserve(values.size());
    for (const auto& value : values) {
        std::ostringstream oss;
        oss << "{\"position\":\"" << escapeJson(value.flooredPosition)
            << "\",\"transformedPoint\":\"" << escapeJson(base64Encode(value.transformedPointEncoded)) << "\"}";
        objects.push_back(oss.str());
    }
    return wrapJsonArray(objects);
}

std::vector<BobTransformedValue> deserializeBobTransformedMessageJson(const std::string& json) {
    auto objects = unwrapJsonArray(json);
    std::vector<BobTransformedValue> values;
    values.reserve(objects.size());
    for (const auto& obj : objects) {
        BobTransformedValue value;
        value.flooredPosition = extractJsonValue(obj, "position");
        auto encoded = extractJsonValue(obj, "transformedPoint");
        value.transformedPointEncoded = base64DecodeVector(encoded);
        values.push_back(std::move(value));
    }
    return values;
}
