// End-to-end tests for the commit-reveal dispute layer, phase 1
// (docs/commit_reveal_spec.md, section 9): deterministic derivation,
// transcript container, recorded session and audit.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "audit.h"
#include "derivation.h"
#include "serialization_utils.h"
#include "session.h"
#include "transcript.h"

extern "C" {
#include <sodium.h>
}

namespace {

std::array<unsigned char, 32> fixedKey(unsigned char fill) {
    std::array<unsigned char, 32> key{};
    key.fill(fill);
    return key;
}

std::vector<unsigned char> readFileBytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    EXPECT_TRUE(in) << "cannot open " << path;
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(in)),
                                      std::istreambuf_iterator<char>());
}

std::string hexEncode(const unsigned char* data, std::size_t size) {
    std::vector<char> buffer(size * 2 + 1);
    sodium_bin2hex(buffer.data(), buffer.size(), data, size);
    return std::string(buffer.data());
}

// Deterministic Ed25519 keys so both runs of the determinism test sign
// identically (crypto_sign_seed_keypair from a fixed seed).
SessionKeys fixedSessionKeys(unsigned char fill) {
    std::array<unsigned char, crypto_sign_SEEDBYTES> seed{};
    seed.fill(fill);
    SessionKeys keys;
    crypto_sign_seed_keypair(keys.publicKey.data(), keys.secretKey.data(), seed.data());
    return keys;
}

// Shared fixture data for one committed turn.
struct SessionFixture {
    std::array<unsigned char, 32> masterKeyP = fixedKey(0x11);
    std::array<unsigned char, 32> masterKeyQ = fixedKey(0x22);
    SessionKeys keysP = fixedSessionKeys(0x33);
    SessionKeys keysQ = fixedSessionKeys(0x44);
    GameId gameId{};
    std::uint64_t turn = 3;
    std::size_t nMax = 8;
    std::vector<std::string> elementsP = {"L1:10 12", "L1:11 12", "L1:40 41"};
    std::vector<std::string> elementsQ = {"L1:10 12", "L1:22 5", "L1:40 41", "L1:7 7"};

    SessionFixture() { gameId.fill(0x55); }

    RecordedExchangeResult run(const std::string& path,
                               const std::vector<std::string>* psiElementsQ = nullptr) const {
        return runRecordedExchange(masterKeyP, masterKeyQ, elementsP, elementsQ, turn, nMax,
                                   gameId, keysP, keysQ, path, nullptr, psiElementsQ);
    }

    AuditOpening openingForQ() const {
        AuditOpening opening;
        opening.accused = 'Q';
        opening.turn = turn;
        opening.nMax = nMax;
        opening.keyIsMasterKey = true;
        opening.key = masterKeyQ;
        opening.elements = elementsQ;
        return opening;
    }

    std::string tempPath(const std::string& name) const {
        return testing::TempDir() + "/" + name;
    }
};

TEST(DerivationTest, SeedsAreDeterministicAndDomainSeparated) {
    const auto master = fixedKey(0x77);
    const auto seed3 = turnSeed(master, 3);
    EXPECT_EQ(seed3, turnSeed(master, 3));
    EXPECT_NE(seed3, turnSeed(master, 4));

    const auto sub = subseed(seed3, 0, 0, 0);
    EXPECT_EQ(sub, subseed(seed3, 0, 0, 0));
    EXPECT_NE(sub, subseed(seed3, 0, 0, 1));
    EXPECT_NE(sub, subseed(seed3, 0, 1, 0));
    EXPECT_NE(sub, subseed(seed3, 1, 0, 0));
}

TEST(DerivationTest, PaddingIsExactDeterministicAndNamespaced) {
    const auto seed = subseed(turnSeed(fixedKey(0x01), 1), 0, 0, 2);
    const std::vector<std::string> elements = {"L1:5 5", "L1:1 2"};

    const auto padded = padElements(elements, 6, seed);
    ASSERT_EQ(padded.size(), 6u);
    EXPECT_TRUE(std::is_sorted(padded.begin(), padded.end()));
    // Same subseed, same dummies: byte-identical output.
    EXPECT_EQ(padded, padElements(elements, 6, seed));

    std::size_t dummies = 0;
    for (const auto& element : padded) {
        if (element.rfind("D:", 0) == 0) {
            ++dummies;
            EXPECT_EQ(element.size(), 2u + 16u);  // "D:" + 16 hex chars
        }
    }
    EXPECT_EQ(dummies, 4u);

    // A different party's subseed yields disjoint dummies.
    const auto otherSeed = subseed(turnSeed(fixedKey(0x02), 1), 0, 0, 2);
    const auto otherPadded = padElements(elements, 6, otherSeed);
    for (const auto& element : otherPadded) {
        if (element.rfind("D:", 0) == 0) {
            EXPECT_EQ(std::count(padded.begin(), padded.end(), element), 0);
        }
    }

    // Oversized input is rejected.
    EXPECT_THROW(padElements(padded, 3, seed), std::runtime_error);
}

TEST(AuditTest, TranscriptsAreByteIdenticalAcrossRuns) {
    SessionFixture fixture;
    const auto pathA = fixture.tempPath("determinism_a.transcript");
    const auto pathB = fixture.tempPath("determinism_b.transcript");

    fixture.run(pathA);
    fixture.run(pathB);

    const auto bytesA = readFileBytes(pathA);
    const auto bytesB = readFileBytes(pathB);
    ASSERT_FALSE(bytesA.empty());
    EXPECT_EQ(bytesA, bytesB);
}

TEST(AuditTest, HonestExchangeIsHonestAndIntersectionCorrect) {
    SessionFixture fixture;
    const auto path = fixture.tempPath("honest.transcript");
    const auto result = fixture.run(path);

    // Intersection through padding: dummies never match, only the two real
    // shared cells appear, in both directions.
    const std::set<std::string> expected = {"L1:10 12", "L1:40 41"};
    EXPECT_EQ(std::set<std::string>(result.intersectionSeenByP.begin(),
                                    result.intersectionSeenByP.end()),
              expected);
    EXPECT_EQ(std::set<std::string>(result.intersectionSeenByQ.begin(),
                                    result.intersectionSeenByQ.end()),
              expected);

    const auto records = readTranscript(path);
    ASSERT_EQ(records.size(), 6u);
    // Every wire set is padded to exactly nMax entries: tag bodies carry
    // exactly nMax tags regardless of the real set sizes (3 and 4 here).
    for (const auto& record : records) {
        if (record.msgType == kMsgTypeTags) {
            const std::string body(record.body.begin(), record.body.end());
            EXPECT_EQ(deserializeBobTagMessage(body).size(), fixture.nMax);
        }
    }

    const auto verdict = auditTranscript(records, fixture.openingForQ(),
                                         fixture.keysP.publicKey, fixture.keysQ.publicKey);
    EXPECT_EQ(verdict.verdict, AuditResult::Verdict::Honest);
    EXPECT_EQ(verdictLine(verdict), "HONEST");
    EXPECT_EQ(verdictExitCode(verdict), 0);

    // Auditing the other party against the same transcript also passes.
    AuditOpening openingP;
    openingP.accused = 'P';
    openingP.turn = fixture.turn;
    openingP.nMax = fixture.nMax;
    openingP.keyIsMasterKey = true;
    openingP.key = fixture.masterKeyP;
    openingP.elements = fixture.elementsP;
    const auto verdictP = auditTranscript(records, openingP, fixture.keysP.publicKey,
                                          fixture.keysQ.publicKey);
    EXPECT_EQ(verdictP.verdict, AuditResult::Verdict::Honest);
}

TEST(AuditTest, ProbeForgeryIsFraudWithPlausibleLocation) {
    SessionFixture fixture;
    const auto path = fixture.tempPath("forged.transcript");

    // Q commits to elementsQ but runs the PSI flights from a set differing in
    // one element (a fabricated probe).
    std::vector<std::string> probeQ = fixture.elementsQ;
    probeQ[1] = "L1:99 99";
    fixture.run(path, &probeQ);

    const auto records = readTranscript(path);
    const auto verdict = auditTranscript(records, fixture.openingForQ(),
                                         fixture.keysP.publicKey, fixture.keysQ.publicKey);
    ASSERT_EQ(verdict.verdict, AuditResult::Verdict::Fraud);
    EXPECT_EQ(verdict.turn, fixture.turn);
    EXPECT_EQ(verdict.level, 0u);
    // First divergent flight is Q's Bob-role tag message in direction 0
    // (P queries Q), the first record Q sends.
    EXPECT_EQ(verdict.dir, 0);
    EXPECT_EQ(verdict.msgType, kMsgTypeTags);
    EXPECT_LT(verdict.byteOffset, records[0].body.size());
    EXPECT_EQ(verdictExitCode(verdict), 2);
}

TEST(AuditTest, TamperedBodyFailsSignatureVerification) {
    SessionFixture fixture;
    const auto path = fixture.tempPath("tampered.transcript");
    fixture.run(path);

    auto records = readTranscript(path);
    ASSERT_EQ(records.size(), 6u);
    records[2].body[10] ^= 0x01;  // flip one byte in a recorded body
    const auto tamperedPath = fixture.tempPath("tampered_rewritten.transcript");
    writeTranscript(tamperedPath, records);

    const auto verdict = auditTranscript(readTranscript(tamperedPath), fixture.openingForQ(),
                                         fixture.keysP.publicKey, fixture.keysQ.publicKey);
    ASSERT_EQ(verdict.verdict, AuditResult::Verdict::SignatureInvalid);
    EXPECT_EQ(verdict.recordIndex, 2u);
    EXPECT_EQ(verdictLine(verdict), "SIGNATURE-INVALID record=2");
    EXPECT_EQ(verdictExitCode(verdict), 3);
}

TEST(AuditTest, WrongOpeningIsRejectedAtStepTwo) {
    SessionFixture fixture;
    const auto path = fixture.tempPath("wrong_opening.transcript");
    fixture.run(path);

    auto opening = fixture.openingForQ();
    opening.elements[0] = "L1:64 64";  // differs from the committed set

    const auto verdict = auditTranscript(readTranscript(path), opening,
                                         fixture.keysP.publicKey, fixture.keysQ.publicKey);
    ASSERT_EQ(verdict.verdict, AuditResult::Verdict::Fraud);
    EXPECT_EQ(verdict.msgType, kMsgTypeCommitmentOpening);
    EXPECT_NE(verdict.note.find("step 2"), std::string::npos);
}

TEST(AuditTest, CliMatchesLibraryVerdicts) {
    // The CLI shares auditTranscript with the library tests above; this
    // exercises the argument parsing, opening-file parsing and exit codes.
    // ctest runs in the build directory, next to the psi_audit binary.
    std::ifstream binary("./psi_audit");
    if (!binary) {
        GTEST_SKIP() << "psi_audit binary not found in working directory";
    }

    SessionFixture fixture;
    const auto honestPath = fixture.tempPath("cli_honest.transcript");
    const auto forgedPath = fixture.tempPath("cli_forged.transcript");
    fixture.run(honestPath);
    std::vector<std::string> probeQ = fixture.elementsQ;
    probeQ[1] = "L1:99 99";
    fixture.run(forgedPath, &probeQ);

    const auto openingPath = fixture.tempPath("cli_opening.txt");
    {
        std::ofstream out(openingPath);
        out << "accused: Q\n"
            << "turn: " << fixture.turn << "\n"
            << "nmax: " << fixture.nMax << "\n"
            << "master: " << hexEncode(fixture.masterKeyQ.data(), fixture.masterKeyQ.size())
            << "\n"
            << "elements:\n";
        for (const auto& element : fixture.elementsQ) {
            out << element << "\n";
        }
    }

    const std::string pkP = hexEncode(fixture.keysP.publicKey.data(),
                                      fixture.keysP.publicKey.size());
    const std::string pkQ = hexEncode(fixture.keysQ.publicKey.data(),
                                      fixture.keysQ.publicKey.size());

    auto runCli = [&](const std::string& transcript) {
        const std::string command = "./psi_audit " + transcript + " " + openingPath + " " +
                                    pkP + " " + pkQ + " >/dev/null 2>&1";
        const int status = std::system(command.c_str());
        return WEXITSTATUS(status);
    };

    EXPECT_EQ(runCli(honestPath), 0);
    EXPECT_EQ(runCli(forgedPath), 2);
}

}  // namespace
