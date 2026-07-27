#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
#include <sodium.h>
}

#include "psi_protocol.h"

namespace {

void ensureSodiumInit() {
    static const bool ok = []() {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialisation failed");
        }
        return true;
    }();
    (void)ok;
}

template <typename Func>
auto measure(double& durationMs, Func&& func) {
    const auto start = std::chrono::steady_clock::now();
    auto result = func();
    const auto end = std::chrono::steady_clock::now();
    durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    return result;
}

std::vector<Unit> bobUnits() {
    return {
        {"u1", 100.0, 100.0},
        {"u2", 200.0, 200.0},
        {"u3", 450.0, 450.0},
    };
}

std::vector<Unit> aliceUnits() {
    return {
        {"u1", 150.0, 150.0},
        {"u2", 250.0, 250.0},
        {"u3", 350.0, 350.0},
        {"u4", 450.0, 450.0},
    };
}

}  // namespace

int main() {
    try {
        ensureSodiumInit();
    } catch (const std::exception& ex) {
        std::cerr << "Failed to initialise libsodium: " << ex.what() << '\n';
        return EXIT_FAILURE;
    }

    try {
        const auto bob = bobUnits();
        const auto alice = aliceUnits();

        double bobSetupMs = 0.0;
        double aliceSetupMs = 0.0;
        double bobResponseMs = 0.0;
        double aliceFinalizeMs = 0.0;

        const auto bobMessage = measure(bobSetupMs, [&]() {
            return bobCreateInitialMessage(bob);
        });

        const auto aliceMessage = measure(aliceSetupMs, [&]() {
            return aliceProcessBobMessage(bobMessage.serialized, alice);
        });

        const auto bobResponse = measure(bobResponseMs, [&]() {
            return bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
        });

        const auto intersections = measure(aliceFinalizeMs, [&]() {
            return aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state);
        });

        std::cout << "PSI smoke test complete\n";
        std::cout << "Bob units: " << bob.size() << ", Alice units: " << alice.size() << '\n';

        if (intersections.empty()) {
            std::cout << "No intersections discovered.\n";
        } else {
            std::cout << "Intersections:\n";
            for (const auto& unit : intersections) {
                std::cout << "  - " << unit.plaintext << '\n';
            }
        }

        std::cout << "Timings (ms):\n"
                  << "  Bob setup: " << bobSetupMs << '\n'
                  << "  Alice setup: " << aliceSetupMs << '\n'
                  << "  Bob response: " << bobResponseMs << '\n'
                  << "  Alice finalise: " << aliceFinalizeMs << '\n';

        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "PSI smoke test failed: " << ex.what() << '\n';
        return EXIT_FAILURE;
    }
}
