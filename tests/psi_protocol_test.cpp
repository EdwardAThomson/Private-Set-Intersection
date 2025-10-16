#include <gtest/gtest.h>

#include "position_utils.h"
#include "psi_protocol.h"
#include "test_helpers.h"

#include <initializer_list>

namespace {

std::vector<Unit> makeUnits(std::initializer_list<Unit> list) {
    return std::vector<Unit>(list);
}

}  // namespace

TEST(PSIProtocolTest, FindsSingleIntersection) {
    ensureSodiumInit();
    ECEnvironment env;

    const auto bobUnits = makeUnits({
        {"b1", 1.2, 3.4},
        {"b2", -5.6, 7.8}
    });
    const auto aliceUnits = makeUnits({
        {"a1", 1.9, 3.1},
        {"a2", 4.2, 8.6},
        {"a3", -5.0, 7.0}
    });

    const auto bobMessage = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    EXPECT_EQ(bobUnits.size(), bobMessage.units.size());

    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, env.group, env.ctx);
    EXPECT_EQ(aliceUnits.size(), aliceMessage.values.size());

    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state, env.group, env.ctx);
    EXPECT_EQ(aliceUnits.size(), bobResponse.values.size());

    const auto decrypted = aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state, env.group, env.ctx);
    ASSERT_EQ(1u, decrypted.size());
    EXPECT_EQ("1 3", decrypted[0].plaintext);
}

TEST(PSIProtocolTest, HandlesNoIntersection) {
    ensureSodiumInit();
    ECEnvironment env;

    const auto bobUnits = makeUnits({
        {"b1", 10.1, 20.2},
        {"b2", 30.3, 40.4}
    });
    const auto aliceUnits = makeUnits({
        {"a1", -1.0, -2.0},
        {"a2", -3.0, -4.0}
    });

    const auto bobMessage = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, env.group, env.ctx);
    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state, env.group, env.ctx);
    const auto decrypted = aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state, env.group, env.ctx);

    EXPECT_TRUE(decrypted.empty());
    EXPECT_EQ(aliceUnits.size(), bobResponse.values.size());
}

TEST(PSIProtocolTest, DeduplicatesMatchesByKey) {
    ensureSodiumInit();
    ECEnvironment env;

    const auto bobUnits = makeUnits({
        {"b1", 1.1, 2.2},
        {"b2", 1.4, 2.8}
    });
    const auto aliceUnits = makeUnits({
        {"a1", 1.9, 2.2},
        {"a2", 5.0, 5.0}
    });

    const auto bobMessage = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, env.group, env.ctx);
    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state, env.group, env.ctx);
    const auto decrypted = aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state, env.group, env.ctx);

    EXPECT_EQ(bobUnits.size(), bobMessage.units.size());
    EXPECT_EQ(aliceUnits.size(), aliceMessage.values.size());
    ASSERT_EQ(1u, decrypted.size());
    EXPECT_EQ(flooredPosition(1.1, 2.2), decrypted[0].plaintext);
}
