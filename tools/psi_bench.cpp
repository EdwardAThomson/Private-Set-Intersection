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
#include <thread>
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

// Optional caches model each party's LOCAL hashToGroup cache. Bob's private
// scalar is still generated fresh inside bobCreateInitialTagMessage on every
// call: the cache never touches wire-visible values, as the security model
// requires.
PhaseTimes runTagMode(const std::vector<Unit>& bobUnits,
                      const std::vector<Unit>& aliceUnits,
                      HashToGroupCache* bobCache = nullptr,
                      HashToGroupCache* aliceCache = nullptr) {
    PhaseTimes t;
    const auto bobMessage =
        timed(t.bobSetupMs, [&]() { return bobCreateInitialTagMessage(bobUnits, bobCache); });
    const auto aliceMessage = timed(t.aliceSetupMs, [&]() {
        return aliceProcessBobTagMessage(bobMessage.serialized, aliceUnits, aliceCache);
    });
    const auto bobResponse = timed(t.bobResponseMs,
                                   [&]() { return bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state); });
    const auto matched = timed(t.aliceFinalizeMs,
                               [&]() { return aliceFinalizeIntersectionTags(bobResponse.serialized, aliceMessage.state); });
    t.bobMessageBytes = bobMessage.serialized.size();
    t.intersections = matched.size();
    return t;
}

void printRow(const std::string& mode, std::size_t size, const PhaseTimes& t, std::size_t expected) {
    std::cout << "| " << std::setw(12) << mode
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

// Per-move scenario: a first full tag-mode exchange at this size warms each
// party's local HashToGroupCache, then k of Bob's elements move and a FRESH
// exchange runs (new private scalar, full tag recompute, as the security
// model requires; only the local element-to-point cache carries over). The
// cold row repeats the fresh exchange with no cache for comparison.
void runPerMoveScenario(std::size_t size, const std::vector<std::size_t>& moveCounts) {
    std::vector<Unit> bobUnits;
    std::vector<Unit> aliceUnits;
    std::size_t expected = 0;
    makeUnits(size, bobUnits, aliceUnits, expected);

    HashToGroupCache bobCache;
    HashToGroupCache aliceCache;
    // First full exchange: warms both local caches.
    (void)runTagMode(bobUnits, aliceUnits, &bobCache, &aliceCache);

    for (const auto k : moveCounts) {
        if (k >= size - static_cast<std::size_t>(static_cast<double>(size) * kOverlapFraction)) {
            continue;  // keep the expected overlap intact
        }

        // Move the last k of Bob's units (outside the overlap region) to
        // guaranteed-fresh positions, simulating incremental movement.
        auto movedBobUnits = bobUnits;
        for (std::size_t i = 0; i < k; ++i) {
            auto& unit = movedBobUnits[movedBobUnits.size() - 1 - i];
            unit.x = static_cast<double>(2000000 + i);
            unit.y = static_cast<double>(3000000 + i);
        }

        const auto cold = runTagMode(movedBobUnits, aliceUnits);
        const auto warm = runTagMode(movedBobUnits, aliceUnits, &bobCache, &aliceCache);

        const std::string label = "k=" + std::to_string(k);
        printRow("mv-" + label + "-cold", size, cold, expected);
        printRow("mv-" + label + "-warm", size, warm, expected);

        if (cold.intersections != expected || warm.intersections != expected) {
            throw std::runtime_error("per-move scenario mismatch at size " + std::to_string(size) +
                                     " k " + std::to_string(k));
        }
    }
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

    const unsigned hardware = std::thread::hardware_concurrency();
    std::cout << "PSI benchmark: secretbox (trial decryption) vs tag (hash-set lookup)\n";
    std::cout << "Overlap fraction: " << kOverlapFraction << ", timings in ms, threads: "
              << (hardware != 0 ? hardware : 1) << "\n\n";
    std::cout << "| mode         | size   | bob_setup  | alice_setup | bob_response | alice_final  | total     | bob_msg_B   | matches |\n";
    std::cout << "|--------------|--------|------------|-------------|--------------|--------------|-----------|-------------|---------|\n";

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

        std::cout << "\nPer-move scenario (tag mode): first exchange warms local HashToGroupCache,\n";
        std::cout << "then k Bob elements move and a fresh exchange runs (new scalar, full tag\n";
        std::cout << "recompute). warm rows reuse only the local hash cache; cold rows do not.\n\n";
        std::cout << "| scenario     | size   | bob_setup  | alice_setup | bob_response | alice_final  | total     | bob_msg_B   | matches |\n";
        std::cout << "|--------------|--------|------------|-------------|--------------|--------------|-----------|-------------|---------|\n";
        for (const auto size : sizes) {
            runPerMoveScenario(size, {2, 32});
        }
    } catch (const std::exception& ex) {
        std::cerr << "Benchmark failed: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
