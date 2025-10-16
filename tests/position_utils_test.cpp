#include <gtest/gtest.h>

#include "position_utils.h"
#include "psi_types.h"

#include <vector>

TEST(PositionUtilsTest, FloorsPositiveCoordinates) {
    EXPECT_EQ("1 2", flooredPosition(1.8, 2.9));
}

TEST(PositionUtilsTest, FloorsNegativeCoordinates) {
    EXPECT_EQ("-2 -4", flooredPosition(-1.2, -3.1));
}

TEST(PositionUtilsTest, ConvertsUnitArrayToStrings) {
    std::vector<Unit> units = {
        {"u1", 1.2, 3.4},
        {"u2", -0.1, 0.9}
    };

    const auto strings = convertToFlooredStrings(units);
    ASSERT_EQ(2u, strings.size());
    EXPECT_EQ("1 3", strings[0]);
    EXPECT_EQ("-1 0", strings[1]);
}
