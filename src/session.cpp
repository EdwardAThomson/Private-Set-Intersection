#include "session.h"

#include <stdexcept>

#include "derivation.h"
#include "psi_protocol.h"

namespace {

std::vector<unsigned char> toBytes(const std::string& s) {
    return std::vector<unsigned char>(s.begin(), s.end());
}

bool isDummy(const std::string& element) {
    return element.rfind("D:", 0) == 0;
}

}  // namespace

SessionKeys generateSessionKeys() {
    if (sodium_init() < 0) {
        throw std::runtime_error("libsodium initialization failed");
    }
    SessionKeys keys;
    crypto_sign_keypair(keys.publicKey.data(), keys.secretKey.data());
    return keys;
}

RecordedExchangeResult runRecordedExchange(
    const std::array<unsigned char, 32>& masterKeyP,
    const std::array<unsigned char, 32>& masterKeyQ,
    const std::vector<std::string>& elementsP,
    const std::vector<std::string>& elementsQ,
    std::uint64_t turn,
    std::size_t nMax,
    const GameId& gameId,
    const SessionKeys& keysP,
    const SessionKeys& keysQ,
    const std::string& transcriptPath,
    const std::vector<std::string>* psiElementsP,
    const std::vector<std::string>* psiElementsQ) {
    const auto seedP = turnSeed(masterKeyP, turn);
    const auto seedQ = turnSeed(masterKeyQ, turn);

    RecordedExchangeResult result;
    // Commitments always cover the party's claimed real set; the psiElements
    // overrides only affect the flights, which is exactly the fraud pattern
    // the audit exists to catch.
    result.commitmentP = computeCommitment(elementsP, seedP);
    result.commitmentQ = computeCommitment(elementsQ, seedQ);

    const std::vector<std::string>& flightElementsP =
        (psiElementsP != nullptr) ? *psiElementsP : elementsP;
    const std::vector<std::string>& flightElementsQ =
        (psiElementsQ != nullptr) ? *psiElementsQ : elementsQ;

    TranscriptWriter writer(transcriptPath);

    // Runs one direction: `alice` learns the intersection from `bob`.
    // Records three signed flights at level 0.
    const std::uint32_t level = 0;
    auto runDirection = [&](std::uint8_t dir,
                            const std::array<unsigned char, 32>& bobSeed,
                            const std::vector<std::string>& bobElements,
                            const Commitment& bobCommitment,
                            const SessionKeys& bobKeys,
                            const std::array<unsigned char, 32>& aliceSeed,
                            const std::vector<std::string>& aliceElements,
                            const Commitment& aliceCommitment,
                            const SessionKeys& aliceKeys) {
        // Fresh DeterministicRng per (turn, level, dir) and per role: the
        // subseeds differ, so the fresh-scalar-per-exchange invariant holds.
        DeterministicRng bobRng(bobSeed, level, dir);
        DeterministicRng aliceRng(aliceSeed, level, dir);

        const auto bobPadded = padElements(bobElements, nMax, subseed(bobSeed, level, dir, 2));
        const auto alicePadded = padElements(aliceElements, nMax, subseed(aliceSeed, level, dir, 2));

        auto makeRecord = [&](std::uint8_t msgType, const Commitment& cSelf,
                              const Commitment& cPeer, const std::string& body) {
            TranscriptRecord record;
            record.gameId = gameId;
            record.turn = turn;
            record.level = level;
            record.dir = dir;
            record.msgType = msgType;
            record.cSelf = cSelf;
            record.cPeer = cPeer;
            record.body = toBytes(body);
            return record;
        };

        auto bobMessage = bobCreateInitialTagMessageFromElements(bobPadded, nullptr, &bobRng);
        writer.append(makeRecord(kMsgTypeTags, bobCommitment, aliceCommitment,
                                 bobMessage.serialized),
                      bobKeys.secretKey);

        auto aliceMessage = aliceProcessBobTagMessageFromElements(bobMessage.serialized,
                                                                  alicePadded, nullptr, &aliceRng);
        writer.append(makeRecord(kMsgTypeBlinded, aliceCommitment, bobCommitment,
                                 aliceMessage.serialized),
                      aliceKeys.secretKey);

        auto bobResponse = bobProcessAliceMessage(aliceMessage.serialized, bobMessage.state);
        writer.append(makeRecord(kMsgTypeTransformed, bobCommitment, aliceCommitment,
                                 bobResponse.serialized),
                      bobKeys.secretKey);

        const auto matches = aliceFinalizeIntersectionTags(bobResponse.serialized,
                                                           aliceMessage.state);
        std::vector<std::string> realMatches;
        for (const auto& match : matches) {
            // Dummies come from each party's own secret subseed and the "D:"
            // namespace, so they never match across parties; filtering here
            // is belt and braces plus keeps demo output clean.
            if (!isDummy(match.element)) {
                realMatches.push_back(match.element);
            }
        }
        return realMatches;
    };

    // dir 0: P queries Q (Q takes the Bob role, P the Alice role).
    result.intersectionSeenByP = runDirection(0, seedQ, flightElementsQ, result.commitmentQ,
                                              keysQ, seedP, flightElementsP, result.commitmentP,
                                              keysP);
    // dir 1: Q queries P.
    result.intersectionSeenByQ = runDirection(1, seedP, flightElementsP, result.commitmentP,
                                              keysP, seedQ, flightElementsQ, result.commitmentQ,
                                              keysQ);
    return result;
}
