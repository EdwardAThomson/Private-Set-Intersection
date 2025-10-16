#include <gtest/gtest.h>

#include "random_utils.h"
#include "test_helpers.h"

#include <array>

TEST(RandomUtilsTest, ReturnsEmptyVectorWhenCountIsZero) {
    ensureSodiumInit();
    const std::array<unsigned char, 32> seed{};  // All zeros
    const auto values = deriveRandomValues(0, seed);
    EXPECT_TRUE(values.empty());
}

TEST(RandomUtilsTest, SequenceIsDeterministicForGivenSeed) {
    ensureSodiumInit();
    std::array<unsigned char, 32> seed{};
    seed[0] = 0x42;

    const auto first = deriveRandomValues(5, seed);
    const auto second = deriveRandomValues(5, seed);
    EXPECT_EQ(first, second);
}

TEST(RandomUtilsTest, DifferentSeedsYieldDifferentOutputs) {
    ensureSodiumInit();
    std::array<unsigned char, 32> seedA{};
    std::array<unsigned char, 32> seedB{};
    seedA[0] = 0x01;
    seedB[0] = 0x02;

    const auto valuesA = deriveRandomValues(3, seedA);
    const auto valuesB = deriveRandomValues(3, seedB);

    ASSERT_EQ(valuesA.size(), valuesB.size());
    EXPECT_NE(valuesA, valuesB);
}
