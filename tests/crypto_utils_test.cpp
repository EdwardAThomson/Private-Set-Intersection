#include <gtest/gtest.h>

#include <cstring>

#include "blake3_utils.h"
#include "crypto_utils.h"
#include "test_helpers.h"

TEST(CryptoUtilsTest, HashToGroupIsDeterministicAndValid) {
    ensureSodiumInit();

    const auto point1 = hashToGroup("hello");
    const auto point2 = hashToGroup("hello");

    EXPECT_EQ(point1, point2);
    EXPECT_EQ(1, crypto_core_ristretto255_is_valid_point(point1.data()));
}

TEST(CryptoUtilsTest, HashToGroupProducesDistinctPointsForDifferentMessages) {
    ensureSodiumInit();

    const auto point1 = hashToGroup("hello");
    const auto point2 = hashToGroup("world");

    EXPECT_NE(point1, point2);
}

// Guards the hash-to-group construction against being "simplified" back to
// H(x)·G. With crypto_core_ristretto255_from_hash, the discrete log of the
// output is unknown; under the old scheme it equalled the SHA-512-derived
// scalar, which let Alice recover b·G from one transcript and enumerate Bob's
// set offline (docs/security_hardening.md, issue 2). If hashToGroup ever
// matches scalar-times-basepoint again, this test fails.
TEST(CryptoUtilsTest, HashToGroupHasNoKnownDiscreteLog) {
    ensureSodiumInit();

    const std::string message = "attack-regression";
    const auto point = hashToGroup(message);

    unsigned char fullHash[crypto_hash_sha512_BYTES];
    ASSERT_EQ(0, crypto_hash_sha512(fullHash,
                                    reinterpret_cast<const unsigned char*>(message.data()),
                                    message.size()));

    // Old construction: scalar = first 32 bytes of SHA-512 (reduced), point = scalar·G.
    RistrettoScalar scalar{};
    unsigned char wide[64] = {0};
    std::memcpy(wide, fullHash, 32);
    crypto_core_ristretto255_scalar_reduce(scalar.data(), wide);

    RistrettoPoint knownDlogPoint{};
    ASSERT_EQ(0, crypto_scalarmult_ristretto255_base(knownDlogPoint.data(), scalar.data()));

    EXPECT_NE(knownDlogPoint, point);
}

TEST(CryptoUtilsTest, HashPointToKeyIsStable) {
    ensureSodiumInit();

    const auto point = hashToGroup("stable");
    const auto key1 = hashPointToKey(point);
    const auto key2 = hashPointToKey(point);

    EXPECT_EQ(key1, key2);
}

TEST(CryptoUtilsTest, HashPointToKeyDiffersForDistinctPoints) {
    ensureSodiumInit();

    const auto key1 = hashPointToKey(hashToGroup("alice"));
    const auto key2 = hashPointToKey(hashToGroup("bob"));

    EXPECT_NE(key1, key2);
}

TEST(CryptoUtilsTest, Blake3DeriveKeyDiffersFromPlainHash) {
    ensureSodiumInit();

    const auto key = hashPointToKey(hashToGroup("derive-key-material"));
    const auto derived = blake3DeriveKey("PSI-membership-tag-v1", key);
    const auto plain = blake3Hash(key);

    EXPECT_NE(derived, plain);
}

TEST(CryptoUtilsTest, KeyToMembershipTagIsDeterministicAndDomainSeparated) {
    ensureSodiumInit();

    const auto point = hashToGroup("membership-tag");
    const auto key = hashPointToKey(point);

    const auto tag1 = keyToMembershipTag(key);
    const auto tag2 = keyToMembershipTag(key);

    EXPECT_EQ(tag1, tag2);
    EXPECT_NE(tag1, key);
    EXPECT_NE(tag1, hashPointToKey(point));
}
