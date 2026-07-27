#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "psi_protocol.h"
#include "serialization_utils.h"

extern "C" {
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

    const auto bobUnits = defaultBobUnits();
    const auto aliceUnits = defaultAliceUnits();

    PhaseTimings timings;

    // Tag mode is the default protocol variant; see docs/security_hardening.md.
    const auto bobMessage = measurePhase(timings.bobSetupMs, [&]() {
        return bobCreateInitialTagMessage(bobUnits);
    });

    const auto aliceMessage = measurePhase(timings.aliceSetupMs, [&]() {
        return aliceProcessBobTagMessage(bobMessage.serialized, aliceUnits);
    });

    const auto bobResponse = measurePhase(timings.bobResponseMs, [&]() {
        return bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
    });

    const auto decrypted = measurePhase(timings.aliceFinalizeMs, [&]() {
        return aliceFinalizeIntersectionTags(bobResponse.serialized, aliceMessage.state);
    });

    printHeader("Bob Units (Bob's local knowledge)");
    for (const auto& unit : bobUnits) {
        std::cout << unit.id << " => (" << unit.x << ", " << unit.y << ")\n";
    }

    printHeader("Alice Units (Alice's local knowledge)");
    for (const auto& unit : aliceUnits) {
        std::cout << unit.id << " => (" << unit.x << ", " << unit.y << ")\n";
    }

    printHeader("Bob -> Alice: Membership Tags");
    std::cout << "count: " << bobMessage.tags.size() << '\n';
    for (std::size_t i = 0; i < bobMessage.tags.size(); ++i) {
        std::cout << "[" << i << "] tag: " << base64Encode(bobMessage.tags[i]) << '\n';
    }
    std::cout << "JSON payload: \n" << serializeBobTagMessageJson(bobMessage.tags) << "\n";

    printHeader("Alice -> Bob: Blinded Points");
    std::cout << "count: " << aliceMessage.values.size() << '\n';
    for (std::size_t i = 0; i < aliceMessage.values.size(); ++i) {
        const auto& value = aliceMessage.values[i];
        std::cout << "[" << i << "] point bytes: " << value.blindedPointEncoded.size() << '\n';
    }
    std::cout << "JSON payload: \n" << serializeAliceBlindedMessageJson(aliceMessage.values) << "\n";

    printHeader("Bob -> Alice: Transformed Points");
    std::cout << "count: " << bobResponse.values.size() << '\n';
    for (std::size_t i = 0; i < bobResponse.values.size(); ++i) {
        const auto& value = bobResponse.values[i];
        std::cout << "[" << i << "] point bytes: " << value.transformedPointEncoded.size() << '\n';
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
