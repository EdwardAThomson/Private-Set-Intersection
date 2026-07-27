// Compares the two phase-1/finalize variants at increasing set sizes:
//   secretbox mode: encrypted elements, finalize by trial decryption (O(A*B))
//   tag mode:       membership tags, finalize by hash-set lookup (O(A))
// Usage: psi_bench [size ...]   (default sizes: 100 500 1000 2000)

#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include "psi_protocol.h"

extern "C" {
#include <sodium.h>
}

namespace {

constexpr double kOverlapFraction = 0.2;

struct PhaseTimes {
    double bobSetupMs{0.0};
    double aliceSetupMs{0.0};
    double bobResponseMs{0.0};
    double aliceFinalizeMs{0.0};
    std::size_t bobMessageBytes{0};
    std::size_t intersections{0};

    double totalMs() const {
        return bobSetupMs + aliceSetupMs + bobResponseMs + aliceFinalizeMs;
    }
};

template <typename Func>
auto timed(double& ms, Func&& func) {
    const auto start = std::chrono::steady_clock::now();
    auto result = func();
    ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
    return result;
}

// Builds Bob's and Alice's unit lists with distinct integer grid positions and
// a fixed overlap fraction. Deterministic seed so runs are comparable.
void makeUnits(std::size_t count,
               std::vector<Unit>& bobUnits,
               std::vector<Unit>& aliceUnits,
               std::size_t& expectedOverlap) {
    std::mt19937 rng(0xC0FFEE);
    std::uniform_int_distribution<int> coord(0, 1000000);

    std::unordered_set<std::string> seen;
    auto freshPosition = [&]() {
        while (true) {
            const int x = coord(rng);
            const int y = coord(rng);
            const std::string key = std::to_string(x) + " " + std::to_string(y);
            if (seen.insert(key).second) {
                return std::pair<int, int>{x, y};
            }
        }
    };

    bobUnits.clear();
    aliceUnits.clear();
    bobUnits.reserve(count);
    aliceUnits.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        const auto [x, y] = freshPosition();
        bobUnits.push_back({"b" + std::to_string(i), static_cast<double>(x), static_cast<double>(y)});
    }

    expectedOverlap = static_cast<std::size_t>(static_cast<double>(count) * kOverlapFraction);
    for (std::size_t i = 0; i < expectedOverlap; ++i) {
        aliceUnits.push_back({"a" + std::to_string(i), bobUnits[i].x, bobUnits[i].y});
    }
    for (std::size_t i = expectedOverlap; i < count; ++i) {
        const auto [x, y] = freshPosition();
        aliceUnits.push_back({"a" + std::to_string(i), static_cast<double>(x), static_cast<double>(y)});
    }
}

PhaseTimes runSecretboxMode(const std::vector<Unit>& bobUnits, const std::vector<Unit>& aliceUnits) {
    PhaseTimes t;
    const auto bobMessage = timed(t.bobSetupMs, [&]() { return bobCreateInitialMessage(bobUnits); });
    const auto aliceMessage =
        timed(t.aliceSetupMs, [&]() { return aliceProcessBobMessage(bobMessage.serialized, aliceUnits); });
    const auto bobResponse = timed(t.bobResponseMs,
                                   [&]() { return bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state); });
    const auto decrypted = timed(t.aliceFinalizeMs,
                                 [&]() { return aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state); });
    t.bobMessageBytes = bobMessage.serialized.size();
    t.intersections = decrypted.size();
    return t;
}

PhaseTimes runTagMode(const std::vector<Unit>& bobUnits, const std::vector<Unit>& aliceUnits) {
    PhaseTimes t;
    const auto bobMessage = timed(t.bobSetupMs, [&]() { return bobCreateInitialTagMessage(bobUnits); });
    const auto aliceMessage =
        timed(t.aliceSetupMs, [&]() { return aliceProcessBobTagMessage(bobMessage.serialized, aliceUnits); });
    const auto bobResponse = timed(t.bobResponseMs,
                                   [&]() { return bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state); });
    const auto matched = timed(t.aliceFinalizeMs,
                               [&]() { return aliceFinalizeIntersectionTags(bobResponse.serialized, aliceMessage.state); });
    t.bobMessageBytes = bobMessage.serialized.size();
    t.intersections = matched.size();
    return t;
}

void printRow(const std::string& mode, std::size_t size, const PhaseTimes& t, std::size_t expected) {
    std::cout << "| " << std::setw(9) << mode
              << " | " << std::setw(6) << size
              << " | " << std::setw(10) << std::fixed << std::setprecision(2) << t.bobSetupMs
              << " | " << std::setw(11) << t.aliceSetupMs
              << " | " << std::setw(12) << t.bobResponseMs
              << " | " << std::setw(12) << t.aliceFinalizeMs
              << " | " << std::setw(9) << t.totalMs()
              << " | " << std::setw(11) << t.bobMessageBytes
              << " | " << std::setw(7) << t.intersections << "/" << expected
              << " |\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium initialisation failed\n";
        return EXIT_FAILURE;
    }

    std::vector<std::size_t> sizes = {100, 500, 1000, 2000};
    if (argc > 1) {
        sizes.clear();
        for (int i = 1; i < argc; ++i) {
            sizes.push_back(static_cast<std::size_t>(std::stoul(argv[i])));
        }
    }

    std::cout << "PSI benchmark: secretbox (trial decryption) vs tag (hash-set lookup)\n";
    std::cout << "Overlap fraction: " << kOverlapFraction << ", timings in ms\n\n";
    std::cout << "| mode      | size   | bob_setup  | alice_setup | bob_response | alice_final  | total     | bob_msg_B   | matches |\n";
    std::cout << "|-----------|--------|------------|-------------|--------------|--------------|-----------|-------------|---------|\n";

    try {
        for (const auto size : sizes) {
            std::vector<Unit> bobUnits;
            std::vector<Unit> aliceUnits;
            std::size_t expected = 0;
            makeUnits(size, bobUnits, aliceUnits, expected);

            const auto secretbox = runSecretboxMode(bobUnits, aliceUnits);
            printRow("secretbox", size, secretbox, expected);

            const auto tag = runTagMode(bobUnits, aliceUnits);
            printRow("tag", size, tag, expected);

            if (secretbox.intersections != expected || tag.intersections != expected) {
                std::cerr << "MISMATCH at size " << size << ": expected " << expected
                          << ", secretbox " << secretbox.intersections
                          << ", tag " << tag.intersections << "\n";
                return EXIT_FAILURE;
            }
        }
    } catch (const std::exception& ex) {
        std::cerr << "Benchmark failed: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
