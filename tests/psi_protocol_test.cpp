#include <gtest/gtest.h>

#include "position_utils.h"
#include "psi_protocol.h"
#include "test_helpers.h"

#include <algorithm>
#include <initializer_list>
#include <set>
#include <string>
#include <unordered_set>

namespace {

std::vector<Unit> makeUnits(std::initializer_list<Unit> list) {
    return std::vector<Unit>(list);
}

// Builds bob/alice sets of `count` units each with exactly `overlap` shared
// integer positions (Bob index i == Alice index i for i < overlap) and all
// other positions distinct across both sets.
void makeLargeSets(std::size_t count,
                   std::size_t overlap,
                   std::vector<Unit>& bobUnits,
                   std::vector<Unit>& aliceUnits) {
    bobUnits.clear();
    aliceUnits.clear();
    for (std::size_t i = 0; i < count; ++i) {
        bobUnits.push_back({"b" + std::to_string(i),
                            static_cast<double>(i), static_cast<double>(i)});
        const std::size_t aliceX = (i < overlap) ? i : i + 1000000;
        aliceUnits.push_back({"a" + std::to_string(i),
                              static_cast<double>(aliceX), static_cast<double>(i)});
    }
}

std::set<std::string> bruteForceIntersection(const std::vector<Unit>& bobUnits,
                                             const std::vector<Unit>& aliceUnits) {
    const auto bobPositions = convertToFlooredStrings(bobUnits);
    const std::unordered_set<std::string> bobSet(bobPositions.begin(), bobPositions.end());

    std::set<std::string> expected;
    for (const auto& position : convertToFlooredStrings(aliceUnits)) {
        if (bobSet.count(position) != 0) {
            expected.insert(position);
        }
    }
    return expected;
}

std::set<std::string> resultElements(const std::vector<MatchedUnit>& results) {
    std::set<std::string> elements;
    for (const auto& match : results) {
        elements.insert(match.element);
    }
    return elements;
}

}  // namespace

TEST(PSIProtocolTest, FindsSingleIntersection) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({
        {"b1", 1.2, 3.4},
        {"b2", -5.6, 7.8}
    });
    const auto aliceUnits = makeUnits({
        {"a1", 1.9, 3.1},
        {"a2", 4.2, 8.6},
        {"a3", -5.0, 7.0}
    });

    const auto bobMessage = bobCreateInitialMessage(bobUnits);
    EXPECT_EQ(bobUnits.size(), bobMessage.units.size());

    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits);
    EXPECT_EQ(aliceUnits.size(), aliceMessage.values.size());

    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
    EXPECT_EQ(aliceUnits.size(), bobResponse.values.size());

    const auto decrypted = aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state);
    ASSERT_EQ(1u, decrypted.size());
    EXPECT_EQ("1 3", decrypted[0].element);
}

TEST(PSIProtocolTest, HandlesNoIntersection) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({
        {"b1", 10.1, 20.2},
        {"b2", 30.3, 40.4}
    });
    const auto aliceUnits = makeUnits({
        {"a1", -1.0, -2.0},
        {"a2", -3.0, -4.0}
    });

    const auto bobMessage = bobCreateInitialMessage(bobUnits);
    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits);
    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
    const auto decrypted = aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state);

    EXPECT_TRUE(decrypted.empty());
    EXPECT_EQ(aliceUnits.size(), bobResponse.values.size());
}

TEST(PSIProtocolTest, DeduplicatesMatchesByKey) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({
        {"b1", 1.1, 2.2},
        {"b2", 1.4, 2.8}
    });
    const auto aliceUnits = makeUnits({
        {"a1", 1.9, 2.2},
        {"a2", 5.0, 5.0}
    });

    const auto bobMessage = bobCreateInitialMessage(bobUnits);
    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits);
    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
    const auto decrypted = aliceFinalizeIntersection(bobResponse.serialized, aliceMessage.state);

    EXPECT_EQ(bobUnits.size(), bobMessage.units.size());
    EXPECT_EQ(aliceUnits.size(), aliceMessage.values.size());
    ASSERT_EQ(1u, decrypted.size());
    EXPECT_EQ(flooredPosition(1.1, 2.2), decrypted[0].element);
}

TEST(PSIProtocolTest, RunPSIProtocolEndToEnd) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({
        {"b1", 100.0, 100.0},
        {"b2", 450.0, 450.0}
    });
    const auto aliceUnits = makeUnits({
        {"a1", 150.0, 150.0},
        {"a2", 450.0, 450.0}
    });

    const auto decrypted = runPSIProtocol(bobUnits, aliceUnits);
    ASSERT_EQ(1u, decrypted.size());
    EXPECT_EQ(flooredPosition(450.0, 450.0), decrypted[0].element);
}

// Wire messages must not leak either party's inputs: the transcript may only
// contain blinded points and authenticated ciphertexts
// (docs/security_hardening.md, issue 1).
TEST(PSIProtocolTest, WireMessagesDoNotContainPlaintextPositions) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({
        {"b1", 123.0, 456.0},
        {"b2", 789.0, 12.0}
    });
    const auto aliceUnits = makeUnits({
        {"a1", 123.0, 456.0},
        {"a2", 345.0, 678.0}
    });

    const auto bobMessage = bobCreateInitialMessage(bobUnits);
    const auto aliceMessage = aliceProcessBobMessage(bobMessage.serialized, aliceUnits);
    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);

    const std::string transcript =
        bobMessage.serialized + aliceMessage.serialized + bobResponse.serialized;

    for (const auto& position : convertToFlooredStrings(bobUnits)) {
        EXPECT_EQ(std::string::npos, transcript.find(position))
            << "Bob position leaked on the wire: " << position;
    }
    for (const auto& position : convertToFlooredStrings(aliceUnits)) {
        EXPECT_EQ(std::string::npos, transcript.find(position))
            << "Alice position leaked on the wire: " << position;
    }
}

TEST(PSIProtocolTagModeTest, FindsSameIntersectionAsSecretboxMode) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({
        {"b1", 1.2, 3.4},
        {"b2", -5.6, 7.8},
        {"b3", 42.0, 42.0}
    });
    const auto aliceUnits = makeUnits({
        {"a1", 1.9, 3.1},
        {"a2", 4.2, 8.6},
        {"a3", 42.5, 42.9}
    });

    const auto secretboxResults = runPSIProtocol(bobUnits, aliceUnits);
    const auto tagResults = runPSIProtocolTags(bobUnits, aliceUnits);

    ASSERT_EQ(secretboxResults.size(), tagResults.size());
    for (std::size_t i = 0; i < tagResults.size(); ++i) {
        EXPECT_EQ(secretboxResults[i].element, tagResults[i].element);
    }
    ASSERT_EQ(2u, tagResults.size());
}

TEST(PSIProtocolTagModeTest, HandlesNoIntersection) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({{"b1", 10.0, 10.0}});
    const auto aliceUnits = makeUnits({{"a1", -10.0, -10.0}});

    EXPECT_TRUE(runPSIProtocolTags(bobUnits, aliceUnits).empty());
}

TEST(PSIProtocolTagModeTest, DeduplicatesMatches) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({
        {"b1", 1.1, 2.2},
        {"b2", 1.4, 2.8}
    });
    const auto aliceUnits = makeUnits({
        {"a1", 1.9, 2.2},
        {"a2", 1.3, 2.5}
    });

    const auto results = runPSIProtocolTags(bobUnits, aliceUnits);
    ASSERT_EQ(1u, results.size());
    EXPECT_EQ(flooredPosition(1.1, 2.2), results[0].element);
}

TEST(PSIProtocolTagModeTest, WireMessagesDoNotContainPlaintextPositions) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({{"b1", 123.0, 456.0}});
    const auto aliceUnits = makeUnits({{"a1", 123.0, 456.0}});

    const auto bobMessage = bobCreateInitialTagMessage(bobUnits);
    const auto aliceMessage = aliceProcessBobTagMessage(bobMessage.serialized, aliceUnits);
    const auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);

    const std::string transcript =
        bobMessage.serialized + aliceMessage.serialized + bobResponse.serialized;
    EXPECT_EQ(std::string::npos, transcript.find("123 456"));
}

// Tags must be fixed-size regardless of element length, so message sizes leak
// only the element count (secretbox ciphertexts leak per-element lengths).
TEST(PSIProtocolTagModeTest, TagsAreFixedSize) {
    ensureSodiumInit();

    const auto shortPos = makeUnits({{"b1", 1.0, 3.0}});
    const auto longPos = makeUnits({{"b1", 123456.0, 654321.0}});

    const auto shortMessage = bobCreateInitialTagMessage(shortPos);
    const auto longMessage = bobCreateInitialTagMessage(longPos);

    EXPECT_EQ(shortMessage.serialized.size(), longMessage.serialized.size());
}

TEST(PSIProtocolTest, RejectsMalformedPointOnWire) {
    ensureSodiumInit();

    const auto bobUnits = makeUnits({{"b1", 1.0, 1.0}});

    const auto bobMessage = bobCreateInitialMessage(bobUnits);

    // A syntactically valid message whose "point" is not a valid ristretto255
    // encoding must be rejected, not silently processed.
    const std::string bogus = "A 1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    EXPECT_THROW(bobProcessAliceMessage(bogus, bobMessage.state), std::runtime_error);
}

// 600 elements is above the parallel threshold (192), so every phase runs on
// the thread-chunked path. The intersection must match a brute-force
// plaintext comparison exactly: same elements, no extras, no misses.
TEST(PSIProtocolParallelTest, LargeTagModeMatchesBruteForce) {
    ensureSodiumInit();

    constexpr std::size_t kCount = 600;
    constexpr std::size_t kOverlap = 150;

    std::vector<Unit> bobUnits;
    std::vector<Unit> aliceUnits;
    makeLargeSets(kCount, kOverlap, bobUnits, aliceUnits);

    const auto expected = bruteForceIntersection(bobUnits, aliceUnits);
    ASSERT_EQ(kOverlap, expected.size());

    const auto results = runPSIProtocolTags(bobUnits, aliceUnits);
    EXPECT_EQ(expected, resultElements(results));
    EXPECT_EQ(kOverlap, results.size());
}

TEST(PSIProtocolParallelTest, LargeSecretboxModeMatchesBruteForce) {
    ensureSodiumInit();

    constexpr std::size_t kCount = 300;
    constexpr std::size_t kOverlap = 60;

    std::vector<Unit> bobUnits;
    std::vector<Unit> aliceUnits;
    makeLargeSets(kCount, kOverlap, bobUnits, aliceUnits);

    const auto expected = bruteForceIntersection(bobUnits, aliceUnits);
    const auto results = runPSIProtocol(bobUnits, aliceUnits);
    EXPECT_EQ(expected, resultElements(results));
}

// A warm local HashToGroupCache must not change the protocol's output in any
// way: same intersection with and without it, in both modes. Bob's scalar is
// still fresh per exchange, so only local hashing work is saved.
TEST(PSIProtocolParallelTest, WarmHashCacheProducesIdenticalIntersections) {
    ensureSodiumInit();

    constexpr std::size_t kCount = 250;
    constexpr std::size_t kOverlap = 50;

    std::vector<Unit> bobUnits;
    std::vector<Unit> aliceUnits;
    makeLargeSets(kCount, kOverlap, bobUnits, aliceUnits);

    HashToGroupCache bobCache;
    HashToGroupCache aliceCache;

    // First exchange warms the caches; second exchange runs entirely on hits.
    const auto coldTag = runPSIProtocolTags(bobUnits, aliceUnits);
    const auto warmTag1 = runPSIProtocolTags(bobUnits, aliceUnits, &bobCache, &aliceCache);
    const auto warmTag2 = runPSIProtocolTags(bobUnits, aliceUnits, &bobCache, &aliceCache);

    EXPECT_EQ(resultElements(coldTag), resultElements(warmTag1));
    EXPECT_EQ(resultElements(coldTag), resultElements(warmTag2));
    EXPECT_EQ(coldTag.size(), warmTag2.size());

    const auto coldBox = runPSIProtocol(bobUnits, aliceUnits);
    const auto warmBox = runPSIProtocol(bobUnits, aliceUnits, &bobCache, &aliceCache);
    EXPECT_EQ(resultElements(coldBox), resultElements(warmBox));
    EXPECT_EQ(resultElements(coldTag), resultElements(warmBox));
}
