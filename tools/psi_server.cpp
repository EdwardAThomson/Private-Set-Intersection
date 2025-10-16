#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "psi_protocol.h"
#include "serialization_utils.h"

extern "C" {
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <sodium.h>
}

namespace {

void ensureSodiumInitialised() {
    static const bool ok = []() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialise libsodium");
        }
        return true;
    }();
    (void)ok;
}

struct ECEnvironment {
    ECEnvironment() {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group) {
            throw std::runtime_error("Failed to create EC_GROUP");
        }
        ctx = BN_CTX_new();
        if (!ctx) {
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to create BN_CTX");
        }
    }

    ~ECEnvironment() {
        if (group) {
            EC_GROUP_free(group);
        }
        if (ctx) {
            BN_CTX_free(ctx);
        }
    }

    EC_GROUP* group{nullptr};
    BN_CTX* ctx{nullptr};
};

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

double parseDouble(const std::string& token) {
    return std::stod(token);
}

std::string extractString(const std::string& object, const std::string& key) {
    const std::string pattern = "\"" + key + "\":\"";
    const auto pos = object.find(pattern);
    if (pos == std::string::npos) {
        throw std::runtime_error("Missing key: " + key);
    }
    std::size_t i = pos + pattern.size();
    std::string value;
    while (i < object.size()) {
        char c = object[i++];
        if (c == '\\') {
            if (i >= object.size()) {
                throw std::runtime_error("Invalid escape in string value");
            }
            char next = object[i++];
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
    throw std::runtime_error("Unterminated string value");
}

double extractNumber(const std::string& object, const std::string& key) {
    const std::string pattern = "\"" + key + "\":";
    const auto pos = object.find(pattern);
    if (pos == std::string::npos) {
        throw std::runtime_error("Missing key: " + key);
    }
    std::size_t i = pos + pattern.size();
    std::size_t end = i;
    while (end < object.size() && (std::isdigit(static_cast<unsigned char>(object[end])) || object[end] == '-' || object[end] == '+' || object[end] == '.' || object[end] == 'e' || object[end] == 'E')) {
        ++end;
    }
    return parseDouble(object.substr(i, end - i));
}

std::vector<Unit> parseUnits(const std::string& body, const std::string& key) {
    const std::string pattern = "\"" + key + "\"";
    auto keyPos = body.find(pattern);
    if (keyPos == std::string::npos) {
        throw std::runtime_error("Missing array: " + key);
    }
    auto arrayStart = body.find('[', keyPos);
    auto arrayEnd = body.find(']', arrayStart);
    if (arrayStart == std::string::npos || arrayEnd == std::string::npos || arrayEnd < arrayStart) {
        throw std::runtime_error("Invalid array structure for " + key);
    }
    std::string inner = body.substr(arrayStart + 1, arrayEnd - arrayStart - 1);
    std::vector<Unit> units;
    std::size_t cursor = 0;
    while (true) {
        auto start = inner.find('{', cursor);
        if (start == std::string::npos) {
            break;
        }
        auto end = inner.find('}', start);
        if (end == std::string::npos) {
            throw std::runtime_error("Unterminated object in " + key);
        }
        auto object = inner.substr(start, end - start + 1);
        Unit unit;
        unit.id = extractString(object, "id");
        unit.x = extractNumber(object, "x");
        unit.y = extractNumber(object, "y");
        units.push_back(unit);
        cursor = end + 1;
    }
    return units;
}

std::string buildResponseJson(const BobInitialMessage& bobMessage,
                              const AliceResponseMessage& aliceMessage,
                              const BobResponseMessage& bobResponse,
                              const std::vector<DecryptedUnit>& decrypted,
                              const std::array<double, 4>& timingsMs) {
    std::ostringstream oss;
    oss << "{\"bob_message\":" << serializeBobEncryptedMessageJson(bobMessage.units)
        << ",\"alice_message\":" << serializeAliceBlindedMessageJson(aliceMessage.values)
        << ",\"bob_response\":" << serializeBobTransformedMessageJson(bobResponse.values)
        << ",\"decrypted\":[";
    for (std::size_t i = 0; i < decrypted.size(); ++i) {
        if (i > 0) {
            oss << ',';
        }
        oss << "\"" << decrypted[i].plaintext << "\"";
    }
    oss << "],\"timings_ms\":{\"bob_setup\":" << timingsMs[0]
        << ",\"alice_setup\":" << timingsMs[1]
        << ",\"bob_response\":" << timingsMs[2]
        << ",\"alice_finalize\":" << timingsMs[3] << "}}";
    return oss.str();
}

std::string handlePsiRequest(const std::string& body, ECEnvironment& env) {
    const auto bobUnits = parseUnits(body, "bob_units");
    const auto aliceUnits = parseUnits(body, "alice_units");

    std::array<double, 4> timings{};

    const auto bobMessage = [&]() {
        const auto start = std::chrono::steady_clock::now();
        auto msg = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
        timings[0] = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        return msg;
    }();

    const auto aliceMessage = [&]() {
        const auto start = std::chrono::steady_clock::now();
        auto msg = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, env.group, env.ctx);
        timings[1] = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        return msg;
    }();

    const auto bobResponse = [&]() {
        const auto start = std::chrono::steady_clock::now();
        auto msg = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state, env.group, env.ctx);
        timings[2] = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        return msg;
    }();

    const auto decrypted = [&]() {
        const auto start = std::chrono::steady_clock::now();
        auto result = aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state, env.group, env.ctx);
        timings[3] = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        return result;
    }();

    return buildResponseJson(bobMessage, aliceMessage, bobResponse, decrypted, timings);
}

std::string buildHttpResponse(const std::string& payload) {
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << payload.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << payload;
    return oss.str();
}

std::string buildErrorResponse(const std::string& message) {
    std::string payload = std::string("{\"error\":\"") + message + "\"}";
    std::ostringstream oss;
    oss << "HTTP/1.1 400 Bad Request\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << payload.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << payload;
    return oss.str();
}

void serveLoop(int serverFd) {
    ECEnvironment env;
    while (true) {
        sockaddr_in clientAddr{};
        socklen_t addrLen = sizeof(clientAddr);
        int clientFd = accept(serverFd, reinterpret_cast<sockaddr*>(&clientAddr), &addrLen);
        if (clientFd < 0) {
            std::perror("accept");
            continue;
        }

        std::string request;
        char buffer[4096];
        ssize_t bytesRead = 0;
        while ((bytesRead = read(clientFd, buffer, sizeof(buffer))) > 0) {
            request.append(buffer, buffer + bytesRead);
            auto headerEnd = request.find("\r\n\r\n");
            if (headerEnd != std::string::npos) {
                // Determine content length
                auto lenPos = request.find("Content-Length:");
                std::size_t contentLength = 0;
                if (lenPos != std::string::npos) {
                    std::size_t lineEnd = request.find("\r\n", lenPos);
                    auto lenStr = request.substr(lenPos + 15, lineEnd - (lenPos + 15));
                    contentLength = static_cast<std::size_t>(std::stoul(trim(lenStr)));
                }
                auto bodyStart = headerEnd + 4;
                if (request.size() >= bodyStart + contentLength) {
                    break;
                }
            }
        }

        std::string response;
        try {
            auto requestLineEnd = request.find("\r\n");
            if (requestLineEnd == std::string::npos) {
                throw std::runtime_error("Malformed HTTP request");
            }
            auto requestLine = request.substr(0, requestLineEnd);
            if (requestLine.find("POST /psi") != 0) {
                throw std::runtime_error("Unsupported endpoint");
            }
            auto headerEnd = request.find("\r\n\r\n");
            if (headerEnd == std::string::npos) {
                throw std::runtime_error("Missing headers terminator");
            }
            auto body = request.substr(headerEnd + 4);
            response = buildHttpResponse(handlePsiRequest(body, env));
        } catch (const std::exception& ex) {
            std::cerr << "Request error: " << ex.what() << '\n';
            response = buildErrorResponse(ex.what());
        }

        ssize_t sent = 0;
        while (sent < static_cast<ssize_t>(response.size())) {
            ssize_t n = write(clientFd, response.data() + sent, response.size() - sent);
            if (n <= 0) {
                break;
            }
            sent += n;
        }
        close(clientFd);
    }
}

}  // namespace

int main() {
    try {
        ensureSodiumInitialised();
    } catch (const std::exception& ex) {
        std::cerr << "libsodium error: " << ex.what() << '\n';
        return 1;
    }

    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        std::perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::perror("setsockopt");
        close(serverFd);
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(8080);

    if (bind(serverFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("bind");
        close(serverFd);
        return 1;
    }

    if (listen(serverFd, 16) < 0) {
        std::perror("listen");
        close(serverFd);
        return 1;
    }

    std::cout << "PSI server listening on http://localhost:8080/psi" << std::endl;
    serveLoop(serverFd);
    close(serverFd);
    return 0;
}
