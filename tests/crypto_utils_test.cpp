#include <gtest/gtest.h>

#include "crypto_utils.h"
#include "test_helpers.h"

#include <vector>

TEST(CryptoUtilsTest, HashToGroupIsDeterministicAndOnCurve) {
    ensureSodiumInit();
    ECEnvironment env;

    ECPointPtr point1(hashToGroup("hello", env.group, env.ctx));
    ECPointPtr point2(hashToGroup("hello", env.group, env.ctx));
    ASSERT_NE(nullptr, point1);
    ASSERT_NE(nullptr, point2);

    EXPECT_EQ(1, EC_POINT_is_on_curve(env.group, point1.get(), env.ctx));
    EXPECT_EQ(1, EC_POINT_is_on_curve(env.group, point2.get(), env.ctx));

    auto encoded1 = encodePoint(env.group, point1.get(), env.ctx);
    auto encoded2 = encodePoint(env.group, point2.get(), env.ctx);
    EXPECT_EQ(encoded1, encoded2);
}

TEST(CryptoUtilsTest, HashToGroupProducesDistinctPointsForDifferentMessages) {
    ensureSodiumInit();
    ECEnvironment env;

    ECPointPtr point1(hashToGroup("hello", env.group, env.ctx));
    ECPointPtr point2(hashToGroup("world", env.group, env.ctx));
    ASSERT_NE(nullptr, point1);
    ASSERT_NE(nullptr, point2);

    auto encoded1 = encodePoint(env.group, point1.get(), env.ctx);
    auto encoded2 = encodePoint(env.group, point2.get(), env.ctx);
    EXPECT_NE(encoded1, encoded2);
}

TEST(CryptoUtilsTest, HashPointToKeyIsStable) {
    ensureSodiumInit();
    ECEnvironment env;

    ECPointPtr point(hashToGroup("stable", env.group, env.ctx));
    ASSERT_NE(nullptr, point);

    const auto key1 = hashPointToKey(point.get(), env.group, env.ctx);
    const auto key2 = hashPointToKey(point.get(), env.group, env.ctx);

    EXPECT_EQ(key1, key2);
}

TEST(CryptoUtilsTest, HashPointToKeyDiffersForDistinctPoints) {
    ensureSodiumInit();
    ECEnvironment env;

    ECPointPtr point1(hashToGroup("alice", env.group, env.ctx));
    ECPointPtr point2(hashToGroup("bob", env.group, env.ctx));
    ASSERT_NE(nullptr, point1);
    ASSERT_NE(nullptr, point2);

    const auto key1 = hashPointToKey(point1.get(), env.group, env.ctx);
    const auto key2 = hashPointToKey(point2.get(), env.group, env.ctx);

    EXPECT_NE(key1, key2);
}
