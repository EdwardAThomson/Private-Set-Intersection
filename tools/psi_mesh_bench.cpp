// Compares flat fine-grid tag-mode PSI against the coarse-to-fine mesh
// cascade (src/mesh_psi.h) on clustered unit placements: units concentrated
// in a few regions of a large map, the realistic game case where cascades
// win because most of the map is never co-occupied.
//
// Usage: psi_mesh_bench [size ...]   (default sizes: 500 2000 5000)

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "mesh_psi.h"

extern "C" {
#include <sodium.h>
}

namespace {

constexpr double kMapSize = 100000.0;
constexpr double kCoarseCell = 400.0;
constexpr double kFineCell = 50.0;
constexpr double kClusterSpread = 500.0;  // stddev of positions around a cluster centre
constexpr int kClusterCount = 10;
constexpr int kBobClusterEnd = 7;     // Bob uses clusters [0, 7)
constexpr int kAliceClusterBegin = 4; // Alice uses clusters [4, 10): clusters 4-6 shared

// Deterministic seed so runs are comparable.
constexpr std::uint32_t kSeed = 0x4D455348;  // "MESH"

void makeClusteredUnits(std::size_t count,
                        std::vector<Unit>& bobUnits,
                        std::vector<Unit>& aliceUnits) {
    std::mt19937 rng(kSeed);
    std::uniform_real_distribution<double> centreCoord(kClusterSpread * 4.0,
                                                       kMapSize - kClusterSpread * 4.0);

    std::vector<std::pair<double, double>> centres;
    centres.reserve(kClusterCount);
    for (int i = 0; i < kClusterCount; ++i) {
        centres.emplace_back(centreCoord(rng), centreCoord(rng));
    }

    std::normal_distribution<double> offset(0.0, kClusterSpread);

    bobUnits.clear();
    aliceUnits.clear();
    bobUnits.reserve(count);
    aliceUnits.reserve(count);

    std::uniform_int_distribution<int> bobCluster(0, kBobClusterEnd - 1);
    std::uniform_int_distribution<int> aliceCluster(kAliceClusterBegin, kClusterCount - 1);

    for (std::size_t i = 0; i < count; ++i) {
        const auto& centre = centres[static_cast<std::size_t>(bobCluster(rng))];
        bobUnits.push_back(
            {"b" + std::to_string(i), centre.first + offset(rng), centre.second + offset(rng)});
    }
    for (std::size_t i = 0; i < count; ++i) {
        const auto& centre = centres[static_cast<std::size_t>(aliceCluster(rng))];
        aliceUnits.push_back(
            {"a" + std::to_string(i), centre.first + offset(rng), centre.second + offset(rng)});
    }
}

void printLevelRow(const std::string& label, const MeshLevelStats& level) {
    std::cout << "  " << std::left << std::setw(14) << label << std::right
              << " cells_in B/A " << std::setw(5) << level.bobCellsIn << "/" << std::setw(5)
              << level.aliceCellsIn << " (of " << std::setw(5) << level.bobCellsTotal << "/"
              << std::setw(5) << level.aliceCellsTotal << ")"
              << "  matches " << std::setw(5) << level.intersectionSize
              << "  time " << std::setw(9) << std::fixed << std::setprecision(2)
              << level.totalMs() << " ms"
              << "  (setup " << level.bobSetupMs << " / blind " << level.aliceSetupMs
              << " / resp " << level.bobResponseMs << " / final " << level.aliceFinalizeMs << ")"
              << "  wire " << std::setw(8) << level.wireBytes << " B\n";
}

void printSummaryRow(const std::string& mode, std::size_t size, const CascadeResult& result) {
    std::cout << "| " << std::left << std::setw(7) << mode << std::right << " | " << std::setw(6)
              << size << " | " << std::setw(10) << std::fixed << std::setprecision(2)
              << result.totalMs() << " | " << std::setw(11) << result.totalWireBytes() << " | "
              << std::setw(12) << result.intersection.size() << " |\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (sodium_init() < 0) {
        std::cerr << "libsodium initialisation failed\n";
        return EXIT_FAILURE;
    }

    std::vector<std::size_t> sizes = {500, 2000, 5000};
    if (argc > 1) {
        sizes.clear();
        for (int i = 1; i < argc; ++i) {
            sizes.push_back(static_cast<std::size_t>(std::stoul(argv[i])));
        }
    }

    std::cout << "Mesh PSI benchmark: flat fine-grid PSI vs coarse-to-fine cascade (tag mode)\n";
    std::cout << "Map " << kMapSize << " x " << kMapSize << ", clusters " << kClusterCount
              << " (shared " << kAliceClusterBegin << ".." << (kBobClusterEnd - 1)
              << "), coarse cell " << kCoarseCell << ", fine cell " << kFineCell
              << ", timings in ms\n\n";

    const MeshConfig flatConfig{{kFineCell}};
    const MeshConfig cascadeConfig{{kCoarseCell, kFineCell}};

    std::cout << "| mode    | units  | total_ms   | wire_bytes  | fine_matches |\n";
    std::cout << "|---------|--------|------------|-------------|--------------|\n";

    try {
        for (const auto size : sizes) {
            std::vector<Unit> bobUnits;
            std::vector<Unit> aliceUnits;
            makeClusteredUnits(size, bobUnits, aliceUnits);

            const auto flat = runCascadePSI(bobUnits, aliceUnits, flatConfig);
            const auto cascade = runCascadePSI(bobUnits, aliceUnits, cascadeConfig);

            if (flat.intersection != cascade.intersection) {
                std::cerr << "MISMATCH at size " << size << ": flat "
                          << flat.intersection.size() << " cells, cascade "
                          << cascade.intersection.size() << " cells\n";
                return EXIT_FAILURE;
            }

            printSummaryRow("flat", size, flat);
            printSummaryRow("cascade", size, cascade);

            std::cout << "  per-level stats (cascade, " << size << " units per side):\n";
            for (const auto& level : cascade.levels) {
                printLevelRow("L" + std::to_string(static_cast<long long>(level.cellSize)),
                              level);
            }
            std::cout << "\n";
        }
    } catch (const std::exception& ex) {
        std::cerr << "Benchmark failed: " << ex.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
