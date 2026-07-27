#include "mesh_psi.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

#include "psi_protocol.h"

namespace {

constexpr double kDivisibilityEpsilon = 1e-9;

long long cellIndex(double value, double cellSize) {
    return static_cast<long long>(std::floor(value / cellSize));
}

// Stable textual form of a cell size for level prefixes ("400", "12.5", ...).
std::string formatCellSize(double cellSize) {
    std::ostringstream out;
    out << cellSize;
    return out.str();
}

// Floor division for cell indices (C++ integer division truncates toward
// zero, which is wrong for negative cells).
long long floorDiv(long long value, long long divisor) {
    long long quotient = value / divisor;
    if ((value % divisor) != 0 && ((value < 0) != (divisor < 0))) {
        --quotient;
    }
    return quotient;
}

std::pair<long long, long long> parseCell(const std::string& cell) {
    std::istringstream in(cell);
    long long cx = 0;
    long long cy = 0;
    if (!(in >> cx >> cy)) {
        throw std::invalid_argument("Malformed cell string: " + cell);
    }
    return {cx, cy};
}

// Sorted unique cell strings occupied by the given units at cellSize.
std::vector<std::string> occupiedCells(const std::vector<Unit>& units, double cellSize) {
    std::set<std::string> cells;
    for (const auto& unit : units) {
        cells.insert(cellForPosition(unit.x, unit.y, cellSize));
    }
    return std::vector<std::string>(cells.begin(), cells.end());
}

// Keeps only the cells whose parent coarse cell survived the previous level.
std::vector<std::string> restrictToParents(const std::vector<std::string>& cells,
                                           double fineCellSize,
                                           double coarseCellSize,
                                           const std::unordered_set<std::string>& allowedParents) {
    std::vector<std::string> kept;
    kept.reserve(cells.size());
    for (const auto& cell : cells) {
        if (allowedParents.count(parentCell(cell, fineCellSize, coarseCellSize)) != 0) {
            kept.push_back(cell);
        }
    }
    return kept;
}

template <typename Func>
auto timed(double& ms, Func&& func) {
    const auto start = std::chrono::steady_clock::now();
    auto result = func();
    ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start)
             .count();
    return result;
}

}  // namespace

void validateMeshConfig(const MeshConfig& config) {
    if (config.cellSizes.empty()) {
        throw std::invalid_argument("MeshConfig must contain at least one cell size");
    }
    for (const double size : config.cellSizes) {
        if (!(size > 0.0)) {
            throw std::invalid_argument("MeshConfig cell sizes must be positive");
        }
    }
    for (std::size_t i = 1; i < config.cellSizes.size(); ++i) {
        const double coarse = config.cellSizes[i - 1];
        const double fine = config.cellSizes[i];
        if (!(fine < coarse)) {
            throw std::invalid_argument(
                "MeshConfig cell sizes must be strictly decreasing (coarse to fine)");
        }
        const double ratio = coarse / fine;
        if (std::abs(ratio - std::round(ratio)) > kDivisibilityEpsilon) {
            throw std::invalid_argument(
                "Each finer cell size must exactly divide the next coarser one");
        }
    }
}

std::string cellForPosition(double x, double y, double cellSize) {
    return std::to_string(cellIndex(x, cellSize)) + " " + std::to_string(cellIndex(y, cellSize));
}

std::string parentCell(const std::string& fineCell,
                       double fineCellSize,
                       double coarseCellSize) {
    const double ratioReal = coarseCellSize / fineCellSize;
    if (std::abs(ratioReal - std::round(ratioReal)) > kDivisibilityEpsilon || ratioReal < 1.0) {
        throw std::invalid_argument("fineCellSize must divide coarseCellSize");
    }
    const long long ratio = static_cast<long long>(std::llround(ratioReal));
    const auto [cx, cy] = parseCell(fineCell);
    return std::to_string(floorDiv(cx, ratio)) + " " + std::to_string(floorDiv(cy, ratio));
}

std::string levelDomainElement(const std::string& cell, double cellSize) {
    return "L" + formatCellSize(cellSize) + ":" + cell;
}

double CascadeResult::totalMs() const {
    double total = 0.0;
    for (const auto& level : levels) {
        total += level.totalMs();
    }
    return total;
}

std::size_t CascadeResult::totalWireBytes() const {
    std::size_t total = 0;
    for (const auto& level : levels) {
        total += level.wireBytes;
    }
    return total;
}

CascadeResult runCascadePSI(const std::vector<Unit>& bobUnits,
                            const std::vector<Unit>& aliceUnits,
                            const MeshConfig& config) {
    validateMeshConfig(config);

    CascadeResult result;
    result.levels.reserve(config.cellSizes.size());

    // Bare cell strings that survived the previous (coarser) level.
    std::vector<std::string> previousIntersection;
    double previousCellSize = 0.0;

    for (std::size_t levelIndex = 0; levelIndex < config.cellSizes.size(); ++levelIndex) {
        const double cellSize = config.cellSizes[levelIndex];

        MeshLevelStats stats;
        stats.cellSize = cellSize;

        auto bobCells = occupiedCells(bobUnits, cellSize);
        auto aliceCells = occupiedCells(aliceUnits, cellSize);
        stats.bobCellsTotal = bobCells.size();
        stats.aliceCellsTotal = aliceCells.size();

        if (levelIndex > 0) {
            // Restrict this level's inputs to cells nested inside a coarse
            // cell that both parties occupied at the previous level. This is
            // the cascade's whole point: the fine-level PSI only runs over
            // the co-occupied portion of the map.
            const std::unordered_set<std::string> allowed(previousIntersection.begin(),
                                                          previousIntersection.end());
            bobCells = restrictToParents(bobCells, cellSize, previousCellSize, allowed);
            aliceCells = restrictToParents(aliceCells, cellSize, previousCellSize, allowed);
        }
        stats.bobCellsIn = bobCells.size();
        stats.aliceCellsIn = aliceCells.size();

        // SECURITY: domain-separate the level. The protocol hashes
        // "L<cellSize>:<cx> <cy>", never the bare cell string, so an element
        // of one level can never collide with an element of another level
        // (or with a raw flooredPosition string) even when the integer
        // coordinates coincide.
        std::vector<std::string> bobElements;
        bobElements.reserve(bobCells.size());
        for (const auto& cell : bobCells) {
            bobElements.push_back(levelDomainElement(cell, cellSize));
        }
        std::vector<std::string> aliceElements;
        aliceElements.reserve(aliceCells.size());
        for (const auto& cell : aliceCells) {
            aliceElements.push_back(levelDomainElement(cell, cellSize));
        }

        // SECURITY: every level MUST be a completely fresh protocol exchange.
        // bobCreateInitialTagMessageFromElements draws a fresh Bob private
        // scalar and aliceProcessBobTagMessageFromElements draws fresh Alice
        // blinding scalars on every call; nothing below caches or reuses
        // keys, tags, or blinded points across levels. Reusing Bob's scalar
        // across levels would let Alice correlate tags between levels and
        // test coarse-level guesses against fine-level tags.
        const auto bobMessage = timed(stats.bobSetupMs, [&]() {
            return bobCreateInitialTagMessageFromElements(bobElements);
        });
        const auto aliceMessage = timed(stats.aliceSetupMs, [&]() {
            return aliceProcessBobTagMessageFromElements(bobMessage.serialized, aliceElements);
        });
        const auto bobResponse = timed(stats.bobResponseMs, [&]() {
            return bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
        });
        const auto matches = timed(stats.aliceFinalizeMs, [&]() {
            return aliceFinalizeIntersectionTags(bobResponse.serialized, aliceMessage.state);
        });

        stats.wireBytes = bobMessage.serialized.size() + aliceMessage.serialized.size() +
                          bobResponse.serialized.size();
        stats.transcript =
            bobMessage.serialized + aliceMessage.serialized + bobResponse.serialized;

        // NOTE: a non-final level's intersection reveals coarse-cell
        // co-occupancy to Alice. That is the designed hierarchical reveal
        // (the same trade-off as the OpenConflict paper's multi-level
        // scheme): learning "we both occupy coarse cell C" is the price paid
        // for never running fine-level PSI outside C.
        previousIntersection.clear();
        previousIntersection.reserve(matches.size());
        for (const auto& match : matches) {
            // Strip the "L<cellSize>:" domain prefix back to the bare cell.
            const auto colon = match.element.find(':');
            previousIntersection.push_back(
                colon == std::string::npos ? match.element : match.element.substr(colon + 1));
        }
        std::sort(previousIntersection.begin(), previousIntersection.end());
        stats.intersectionSize = previousIntersection.size();
        previousCellSize = cellSize;

        result.levels.push_back(std::move(stats));
    }

    result.intersection = std::move(previousIntersection);
    return result;
}
