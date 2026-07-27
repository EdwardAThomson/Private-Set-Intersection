#include <gtest/gtest.h>

#include "mesh_psi.h"
#include "test_helpers.h"

#include <algorithm>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

const MeshConfig kTwoLevel{{400.0, 50.0}};
const MeshConfig kFlatFine{{50.0}};

// Ground truth: plain (non-private) intersection of the parties' occupied
// fine cells, computed directly from the inputs.
std::vector<std::string> plaintextFineIntersection(const std::vector<Unit>& bobUnits,
                                                   const std::vector<Unit>& aliceUnits,
                                                   double cellSize) {
    std::set<std::string> bobCells;
    for (const auto& unit : bobUnits) {
        bobCells.insert(cellForPosition(unit.x, unit.y, cellSize));
    }
    std::set<std::string> both;
    for (const auto& unit : aliceUnits) {
        const auto cell = cellForPosition(unit.x, unit.y, cellSize);
        if (bobCells.count(cell) != 0) {
            both.insert(cell);
        }
    }
    return std::vector<std::string>(both.begin(), both.end());
}

std::vector<Unit> makeClusteredUnits(const std::string& prefix,
                                     std::size_t count,
                                     std::uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_int_distribution<int> cluster(0, 3);
    std::normal_distribution<double> offset(0.0, 300.0);
    const double centres[4][2] = {
        {1000.0, 1000.0}, {9000.0, 2000.0}, {3000.0, 8000.0}, {7500.0, 7500.0}};

    std::vector<Unit> units;
    units.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const auto& centre = centres[cluster(rng)];
        units.push_back({prefix + std::to_string(i), centre[0] + offset(rng),
                         centre[1] + offset(rng)});
    }
    return units;
}

}  // namespace

TEST(MeshConfigTest, RejectsInvalidConfigs) {
    EXPECT_THROW(validateMeshConfig(MeshConfig{{}}), std::invalid_argument);
    EXPECT_THROW(validateMeshConfig(MeshConfig{{0.0}}), std::invalid_argument);
    EXPECT_THROW(validateMeshConfig(MeshConfig{{-50.0}}), std::invalid_argument);
    // Not strictly decreasing.
    EXPECT_THROW(validateMeshConfig(MeshConfig{{50.0, 400.0}}), std::invalid_argument);
    EXPECT_THROW(validateMeshConfig(MeshConfig{{50.0, 50.0}}), std::invalid_argument);
    // Finer size does not divide the coarser one.
    EXPECT_THROW(validateMeshConfig(MeshConfig{{400.0, 30.0}}), std::invalid_argument);
    EXPECT_THROW(validateMeshConfig(MeshConfig{{100.0, 40.0}}), std::invalid_argument);
}

TEST(MeshConfigTest, AcceptsValidConfigs) {
    EXPECT_NO_THROW(validateMeshConfig(MeshConfig{{50.0}}));
    EXPECT_NO_THROW(validateMeshConfig(kTwoLevel));
    EXPECT_NO_THROW(validateMeshConfig(MeshConfig{{800.0, 200.0, 50.0}}));
    EXPECT_NO_THROW(validateMeshConfig(MeshConfig{{10.0, 2.5}}));
}

TEST(MeshCellTest, MapsPositionsToCells) {
    EXPECT_EQ("1 -1", cellForPosition(75.0, -30.0, 50.0));
    EXPECT_EQ("0 0", cellForPosition(0.0, 49.9, 50.0));
    EXPECT_EQ("-1 -1", cellForPosition(-0.1, -50.0, 50.0));
    EXPECT_EQ("2 1", cellForPosition(999.0, 400.0, 400.0));
}

TEST(MeshCellTest, ComputesParentCells) {
    // Ratio 400 / 50 = 8. Floor division must be used for negative cells.
    EXPECT_EQ("0 0", parentCell("7 7", 50.0, 400.0));
    EXPECT_EQ("1 0", parentCell("8 3", 50.0, 400.0));
    EXPECT_EQ("-1 -1", parentCell("-1 -8", 50.0, 400.0));
    EXPECT_EQ("-2 0", parentCell("-9 0", 50.0, 400.0));
    // A position's fine cell must nest inside its coarse cell.
    const double x = -123.4;
    const double y = 987.6;
    EXPECT_EQ(cellForPosition(x, y, 400.0), parentCell(cellForPosition(x, y, 50.0), 50.0, 400.0));
    EXPECT_THROW(parentCell("1 1", 30.0, 400.0), std::invalid_argument);
}

TEST(MeshCellTest, DomainElementIsLevelPrefixed) {
    EXPECT_EQ("L400:3 5", levelDomainElement("3 5", 400.0));
    EXPECT_EQ("L50:3 5", levelDomainElement("3 5", 50.0));
    // Same cell coordinates at two levels must map to different elements.
    EXPECT_NE(levelDomainElement("3 5", 400.0), levelDomainElement("3 5", 50.0));
}

TEST(MeshCascadeTest, MatchesFlatPSIOnClusteredInputs) {
    ensureSodiumInit();

    const auto bobUnits = makeClusteredUnits("b", 60, 1234);
    const auto aliceUnits = makeClusteredUnits("a", 60, 5678);

    const auto cascade = runCascadePSI(bobUnits, aliceUnits, kTwoLevel);
    const auto flat = runCascadePSI(bobUnits, aliceUnits, kFlatFine);
    const auto expected = plaintextFineIntersection(bobUnits, aliceUnits, 50.0);

    EXPECT_EQ(expected, flat.intersection);
    EXPECT_EQ(expected, cascade.intersection);

    ASSERT_EQ(2u, cascade.levels.size());
    // The coarse level must have pruned the fine level's inputs.
    EXPECT_LE(cascade.levels[1].bobCellsIn, cascade.levels[1].bobCellsTotal);
    EXPECT_LE(cascade.levels[1].aliceCellsIn, cascade.levels[1].aliceCellsTotal);
}

TEST(MeshCascadeTest, MatchesFlatPSIWithThreeLevels) {
    ensureSodiumInit();

    const auto bobUnits = makeClusteredUnits("b", 40, 42);
    const auto aliceUnits = makeClusteredUnits("a", 40, 43);

    const auto cascade = runCascadePSI(bobUnits, aliceUnits, MeshConfig{{800.0, 200.0, 50.0}});
    const auto expected = plaintextFineIntersection(bobUnits, aliceUnits, 50.0);

    EXPECT_EQ(expected, cascade.intersection);
    ASSERT_EQ(3u, cascade.levels.size());
}

TEST(MeshCascadeTest, EmptyIntersectionWhenPartiesAreFarApart) {
    ensureSodiumInit();

    const std::vector<Unit> bobUnits = {{"b1", 100.0, 100.0}, {"b2", 220.0, 180.0}};
    const std::vector<Unit> aliceUnits = {{"a1", 90000.0, 90000.0}, {"a2", 91000.0, 90500.0}};

    const auto cascade = runCascadePSI(bobUnits, aliceUnits, kTwoLevel);
    const auto flat = runCascadePSI(bobUnits, aliceUnits, kFlatFine);

    EXPECT_TRUE(cascade.intersection.empty());
    EXPECT_TRUE(flat.intersection.empty());
    // The coarse level found nothing, so the fine level ran over empty sets.
    ASSERT_EQ(2u, cascade.levels.size());
    EXPECT_EQ(0u, cascade.levels[0].intersectionSize);
    EXPECT_EQ(0u, cascade.levels[1].bobCellsIn);
    EXPECT_EQ(0u, cascade.levels[1].aliceCellsIn);
}

TEST(MeshCascadeTest, EmptyFineIntersectionDespiteCoarseOverlap) {
    ensureSodiumInit();

    // Same 400-cell (cell "0 0"), but disjoint 50-cells.
    const std::vector<Unit> bobUnits = {{"b1", 10.0, 10.0}};
    const std::vector<Unit> aliceUnits = {{"a1", 310.0, 310.0}};

    const auto cascade = runCascadePSI(bobUnits, aliceUnits, kTwoLevel);
    const auto flat = runCascadePSI(bobUnits, aliceUnits, kFlatFine);

    ASSERT_EQ(2u, cascade.levels.size());
    EXPECT_EQ(1u, cascade.levels[0].intersectionSize);
    EXPECT_TRUE(cascade.intersection.empty());
    EXPECT_TRUE(flat.intersection.empty());
}

TEST(MeshCascadeTest, FullOverlapReturnsAllFineCells) {
    ensureSodiumInit();

    std::vector<Unit> bobUnits;
    for (int i = 0; i < 12; ++i) {
        bobUnits.push_back({"b" + std::to_string(i), 100.0 * i + 25.0, 60.0 * i + 10.0});
    }
    auto aliceUnits = bobUnits;  // identical positions: full overlap

    const auto cascade = runCascadePSI(bobUnits, aliceUnits, kTwoLevel);
    const auto flat = runCascadePSI(bobUnits, aliceUnits, kFlatFine);
    const auto expected = plaintextFineIntersection(bobUnits, aliceUnits, 50.0);

    EXPECT_FALSE(expected.empty());
    EXPECT_EQ(expected, cascade.intersection);
    EXPECT_EQ(expected, flat.intersection);
}

// No raw position, no bare cell string, and no domain-separated element may
// ever appear in any level's serialized wire messages: the transcript must
// contain only blinded points and membership tags.
TEST(MeshCascadeTest, TranscriptsNeverContainPlaintext) {
    ensureSodiumInit();

    const std::vector<Unit> bobUnits = {
        {"b1", 12345.0, 67890.0}, {"b2", 12395.0, 67910.0}, {"b3", 4321.0, 8765.0}};
    const std::vector<Unit> aliceUnits = {
        {"a1", 12345.0, 67890.0}, {"a2", 55555.0, 44444.0}};

    const auto cascade = runCascadePSI(bobUnits, aliceUnits, kTwoLevel);
    ASSERT_EQ(2u, cascade.levels.size());

    std::string transcript;
    for (const auto& level : cascade.levels) {
        EXPECT_FALSE(level.transcript.empty());
        transcript += level.transcript;
    }

    std::vector<std::string> forbidden;
    for (const auto& unit : bobUnits) {
        forbidden.push_back(std::to_string(static_cast<long long>(unit.x)) + " " +
                            std::to_string(static_cast<long long>(unit.y)));
        for (const double size : kTwoLevel.cellSizes) {
            forbidden.push_back(cellForPosition(unit.x, unit.y, size));
            forbidden.push_back(levelDomainElement(cellForPosition(unit.x, unit.y, size), size));
        }
    }
    for (const auto& unit : aliceUnits) {
        forbidden.push_back(std::to_string(static_cast<long long>(unit.x)) + " " +
                            std::to_string(static_cast<long long>(unit.y)));
        for (const double size : kTwoLevel.cellSizes) {
            forbidden.push_back(cellForPosition(unit.x, unit.y, size));
            forbidden.push_back(levelDomainElement(cellForPosition(unit.x, unit.y, size), size));
        }
    }

    for (const auto& needle : forbidden) {
        EXPECT_EQ(std::string::npos, transcript.find(needle))
            << "Plaintext leaked on the wire: " << needle;
    }
}
