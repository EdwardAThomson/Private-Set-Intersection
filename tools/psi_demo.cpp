#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
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

void ensureSodiumInit() {
    static const bool initialised = []() {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialisation failed");
        }
        return true;
    }();
    (void)initialised;
}

struct PhaseTimings {
    double bobSetupMs{0.0};
    double aliceSetupMs{0.0};
    double bobResponseMs{0.0};
    double aliceFinalizeMs{0.0};
};

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

template <typename Func>
auto measurePhase(double& durationMs, Func&& func) {
    const auto start = std::chrono::steady_clock::now();
    auto result = func();
    const auto end = std::chrono::steady_clock::now();
    durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    return result;
}

std::vector<Unit> defaultBobUnits() {
    return {
        {"u1", 100.0, 100.0},
        {"u2", 200.0, 200.0},
        {"u3", 450.0, 450.0},
    };
}

std::vector<Unit> defaultAliceUnits() {
    return {
        {"u1", 150.0, 150.0},
        {"u2", 250.0, 250.0},
        {"u3", 350.0, 350.0},
        {"u4", 450.0, 450.0},
        {"u5", 451.0, 450.0},
        {"u6", 452.0, 450.0},
        {"u7", 453.0, 450.0},
        {"u8", 454.0, 450.0},
        {"u9", 455.0, 450.0},
    };
}

void printHeader(const std::string& title) {
    std::cout << "\n=== " << title << " ===\n";
}

}  // namespace

int main() {
    try {
        ensureSodiumInit();
    } catch (const std::exception& ex) {
        std::cerr << "Failed to initialise libsodium: " << ex.what() << '\n';
        return 1;
    }

    ECEnvironment env;
    const auto bobUnits = defaultBobUnits();
    const auto aliceUnits = defaultAliceUnits();

    PhaseTimings timings;

    const auto bobMessage = measurePhase(timings.bobSetupMs, [&]() {
        return bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    });

    const auto aliceMessage = measurePhase(timings.aliceSetupMs, [&]() {
        return aliceProcessBobMessage(bobMessage.serialized, aliceUnits, env.group, env.ctx);
    });

    const auto bobResponse = measurePhase(timings.bobResponseMs, [&]() {
        return bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state, env.group, env.ctx);
    });

    const auto decrypted = measurePhase(timings.aliceFinalizeMs, [&]() {
        return aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state, env.group, env.ctx);
    });

    printHeader("Bob Units (plaintext)");
    for (const auto& unit : bobUnits) {
        std::cout << unit.id << " => (" << unit.x << ", " << unit.y << ")\n";
    }

    printHeader("Alice Units (plaintext)");
    for (const auto& unit : aliceUnits) {
        std::cout << unit.id << " => (" << unit.x << ", " << unit.y << ")\n";
    }

    printHeader("Bob -> Alice: Encrypted Units");
    std::cout << "count: " << bobMessage.units.size() << '\n';
    for (std::size_t i = 0; i < bobMessage.units.size(); ++i) {
        const auto& entry = bobMessage.units[i];
        std::cout << "[" << i << "] position: " << entry.flooredPosition
                  << ", ciphertext bytes: " << entry.ciphertext.ciphertext.size()
                  << ", nonce: " << base64Encode(entry.ciphertext.nonce) << '\n';
    }
    std::cout << "JSON payload: \n" << serializeBobEncryptedMessageJson(bobMessage.units) << "\n";

    printHeader("Alice -> Bob: Blinded Points");
    std::cout << "count: " << aliceMessage.values.size() << '\n';
    for (std::size_t i = 0; i < aliceMessage.values.size(); ++i) {
        const auto& value = aliceMessage.values[i];
        std::cout << "[" << i << "] position: " << value.flooredPosition
                  << ", point bytes: " << value.blindedPointEncoded.size() << '\n';
    }
    std::cout << "JSON payload: \n" << serializeAliceBlindedMessageJson(aliceMessage.values) << "\n";

    printHeader("Bob -> Alice: Transformed Points");
    std::cout << "count: " << bobResponse.values.size() << '\n';
    for (std::size_t i = 0; i < bobResponse.values.size(); ++i) {
        const auto& value = bobResponse.values[i];
        std::cout << "[" << i << "] position: " << value.flooredPosition
                  << ", point bytes: " << value.transformedPointEncoded.size() << '\n';
    }
    std::cout << "JSON payload: \n" << serializeBobTransformedMessageJson(bobResponse.values) << "\n";

    printHeader("Alice Finalisation");
    if (decrypted.empty()) {
        std::cout << "no intersections found\n";
    } else {
        for (const auto& unit : decrypted) {
            std::cout << "intersection: " << unit.plaintext << '\n';
        }
    }

    printHeader("Timings (ms)");
    std::cout << "Bob setup: " << timings.bobSetupMs << '\n'
              << "Alice setup: " << timings.aliceSetupMs << '\n'
              << "Bob response: " << timings.bobResponseMs << '\n'
              << "Alice finalise: " << timings.aliceFinalizeMs << '\n';

    return 0;
}
