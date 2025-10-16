#include <gtest/gtest.h>

#include "psi_protocol.h"
#include "serialization_utils.h"
#include "test_helpers.h"

#include <string>
#include <vector>
#include <stdexcept>

TEST(SerializationUtilsTest, BobEncryptedRoundTrip) {
    ensureSodiumInit();
    ECEnvironment env;

    std::vector<Unit> bobUnits = {
        {"b1", 1.2, 3.4},
        {"b2", 5.6, 7.8}
    };

    auto bobMessage = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    const auto serialized = serializeBobEncryptedMessage(bobMessage.units);
    const auto decoded = deserializeBobEncryptedMessage(serialized);

    ASSERT_EQ(bobMessage.units.size(), decoded.size());
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        EXPECT_EQ(bobMessage.units[i].flooredPosition, decoded[i].flooredPosition);
        EXPECT_EQ(bobMessage.units[i].ciphertext.ciphertext, decoded[i].ciphertext.ciphertext);
        EXPECT_EQ(bobMessage.units[i].ciphertext.nonce, decoded[i].ciphertext.nonce);
    }
}

TEST(SerializationUtilsTest, AliceBlindedRoundTrip) {
    ensureSodiumInit();
    ECEnvironment env;

    std::vector<Unit> bobUnits = {
        {"b1", 0.0, 0.0}
    };
    std::vector<Unit> aliceUnits = {
        {"a1", 1.0, 1.0},
        {"a2", 2.0, 2.0}
    };

    const auto bobMessage = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, env.group, env.ctx);
    const auto serialized = serializeAliceBlindedMessage(aliceMessage.values);
    const auto decoded = deserializeAliceBlindedMessage(serialized);

    ASSERT_EQ(aliceMessage.values.size(), decoded.size());
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        EXPECT_EQ(aliceMessage.values[i].flooredPosition, decoded[i].flooredPosition);
        EXPECT_EQ(aliceMessage.values[i].blindedPointEncoded, decoded[i].blindedPointEncoded);
    }
}

TEST(SerializationUtilsTest, BobTransformedRoundTrip) {
    ensureSodiumInit();
    ECEnvironment env;

    std::vector<Unit> bobUnits = {
        {"b1", 0.0, 0.0}
    };
    std::vector<Unit> aliceUnits = {
        {"a1", 1.0, 1.0}
    };

    const auto bobMessage = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, env.group, env.ctx);
    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state, env.group, env.ctx);
    const auto serialized = serializeBobTransformedMessage(bobResponse.values);
    const auto decoded = deserializeBobTransformedMessage(serialized);

    ASSERT_EQ(bobResponse.values.size(), decoded.size());
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        EXPECT_EQ(bobResponse.values[i].flooredPosition, decoded[i].flooredPosition);
        EXPECT_EQ(bobResponse.values[i].transformedPointEncoded, decoded[i].transformedPointEncoded);
    }
}

TEST(SerializationUtilsTest, BobEncryptedJsonRoundTrip) {
    ensureSodiumInit();
    ECEnvironment env;

    std::vector<Unit> bobUnits = {
        {"b1", 1.2, 3.4},
        {"b2", 5.6, 7.8}
    };

    auto bobMessage = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    const auto json = serializeBobEncryptedMessageJson(bobMessage.units);
    const auto decoded = deserializeBobEncryptedMessageJson(json);

    ASSERT_EQ(bobMessage.units.size(), decoded.size());
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        EXPECT_EQ(bobMessage.units[i].flooredPosition, decoded[i].flooredPosition);
        EXPECT_EQ(bobMessage.units[i].ciphertext.ciphertext, decoded[i].ciphertext.ciphertext);
        EXPECT_EQ(bobMessage.units[i].ciphertext.nonce, decoded[i].ciphertext.nonce);
    }
}

TEST(SerializationUtilsTest, AliceBlindedJsonRoundTrip) {
    ensureSodiumInit();
    ECEnvironment env;

    std::vector<Unit> bobUnits = {
        {"b1", 0.0, 0.0}
    };
    std::vector<Unit> aliceUnits = {
        {"a1", 1.0, 1.0},
        {"a2", 2.0, 2.0}
    };

    const auto bobMessage = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, env.group, env.ctx);

    const auto json = serializeAliceBlindedMessageJson(aliceMessage.values);
    const auto decoded = deserializeAliceBlindedMessageJson(json);

    ASSERT_EQ(aliceMessage.values.size(), decoded.size());
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        EXPECT_EQ(aliceMessage.values[i].flooredPosition, decoded[i].flooredPosition);
        EXPECT_EQ(aliceMessage.values[i].blindedPointEncoded, decoded[i].blindedPointEncoded);
    }
}

TEST(SerializationUtilsTest, BobTransformedJsonRoundTrip) {
    ensureSodiumInit();
    ECEnvironment env;

    std::vector<Unit> bobUnits = {
        {"b1", 0.0, 0.0}
    };
    std::vector<Unit> aliceUnits = {
        {"a1", 1.0, 1.0}
    };

    const auto bobMessage = bobCreateInitialMessage(bobUnits, env.group, env.ctx);
    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits, env.group, env.ctx);
    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state, env.group, env.ctx);

    const auto json = serializeBobTransformedMessageJson(bobResponse.values);
    const auto decoded = deserializeBobTransformedMessageJson(json);

    ASSERT_EQ(bobResponse.values.size(), decoded.size());
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        EXPECT_EQ(bobResponse.values[i].flooredPosition, decoded[i].flooredPosition);
        EXPECT_EQ(bobResponse.values[i].transformedPointEncoded, decoded[i].transformedPointEncoded);
    }
}

TEST(SerializationUtilsTest, BobEncryptedDeserialiseRejectsBadHeader) {
    ensureSodiumInit();
    EXPECT_THROW(deserializeBobEncryptedMessage("X 0\n"), std::runtime_error);
}

TEST(SerializationUtilsTest, BobEncryptedDeserialiseRejectsBadCount) {
    ensureSodiumInit();
    EXPECT_THROW(deserializeBobEncryptedMessage("B not-a-number\n"), std::runtime_error);
}

TEST(SerializationUtilsTest, BobEncryptedDeserialiseRejectsBadBase64) {
    ensureSodiumInit();
    std::string message = "B 1\n100 100\n@@@\nAAAA\n";
    EXPECT_THROW(deserializeBobEncryptedMessage(message), std::runtime_error);
}

TEST(SerializationUtilsTest, AliceBlindedJsonRejectsMissingKey) {
    ensureSodiumInit();
    std::string json = R"({"items":[{"position":"100 100"}]})";
    EXPECT_THROW(deserializeAliceBlindedMessageJson(json), std::runtime_error);
}

TEST(SerializationUtilsTest, BobTransformedJsonRejectsInvalidStructure) {
    ensureSodiumInit();
    std::string json = R"({"wrong":[{}]})";
    EXPECT_THROW(deserializeBobTransformedMessageJson(json), std::runtime_error);
}
