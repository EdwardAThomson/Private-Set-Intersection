#include "audit.h"

#include <algorithm>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>

#include "derivation.h"
#include "psi_protocol.h"

namespace {

// dir 0: P queries Q, so Q takes the Bob role; dir 1: P takes it.
char bobParty(std::uint8_t dir) {
    return dir == 0 ? 'Q' : 'P';
}

char senderOf(const TranscriptRecord& record) {
    const char bob = bobParty(record.dir);
    const char alice = (bob == 'P') ? 'Q' : 'P';
    // Tags and transformed points are Bob-role flights; blinded points are
    // the Alice-role flight.
    return (record.msgType == kMsgTypeBlinded) ? alice : bob;
}

std::array<unsigned char, 32> hexDecode32(const std::string& hex) {
    if (hex.size() != 64) {
        throw std::runtime_error("Expected 64 hex characters, got " + std::to_string(hex.size()));
    }
    auto nibble = [](char c) -> unsigned char {
        if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(c - 'A' + 10);
        throw std::runtime_error("Invalid hex character");
    };
    std::array<unsigned char, 32> out{};
    for (std::size_t i = 0; i < 32; ++i) {
        out[i] = static_cast<unsigned char>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return out;
}

std::string trim(const std::string& s) {
    const auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return "";
    }
    const auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

// First differing byte offset between the recorded body and the recomputed
// bytes; a length difference mismatches at the shorter length.
bool firstMismatch(const std::vector<unsigned char>& recorded,
                   const std::string& recomputed,
                   std::size_t& offset) {
    const std::size_t common = std::min(recorded.size(), recomputed.size());
    for (std::size_t i = 0; i < common; ++i) {
        if (recorded[i] != static_cast<unsigned char>(recomputed[i])) {
            offset = i;
            return true;
        }
    }
    if (recorded.size() != recomputed.size()) {
        offset = common;
        return true;
    }
    return false;
}

AuditResult fraudAt(const TranscriptRecord& record, std::size_t byteOffset,
                    const std::string& note) {
    AuditResult result;
    result.verdict = AuditResult::Verdict::Fraud;
    result.turn = record.turn;
    result.level = record.level;
    result.dir = record.dir;
    result.msgType = record.msgType;
    result.byteOffset = byteOffset;
    result.note = note;
    return result;
}

std::string bodyToString(const std::vector<unsigned char>& body) {
    return std::string(body.begin(), body.end());
}

}  // namespace

AuditOpening parseOpeningFile(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("Cannot open opening file: " + path);
    }

    AuditOpening opening;
    bool haveAccused = false;
    bool haveTurn = false;
    bool haveNMax = false;
    bool haveKey = false;
    bool inElements = false;

    std::string line;
    while (std::getline(in, line)) {
        if (inElements) {
            const std::string element = trim(line);
            if (!element.empty()) {
                opening.elements.push_back(element);
            }
            continue;
        }
        const std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }
        const auto colon = trimmed.find(':');
        if (colon == std::string::npos) {
            throw std::runtime_error("Malformed opening line: " + trimmed);
        }
        const std::string keyName = trim(trimmed.substr(0, colon));
        const std::string value = trim(trimmed.substr(colon + 1));

        if (keyName == "accused") {
            if (value != "P" && value != "Q") {
                throw std::runtime_error("accused must be P or Q");
            }
            opening.accused = value[0];
            haveAccused = true;
        } else if (keyName == "turn") {
            opening.turn = std::stoull(value);
            haveTurn = true;
        } else if (keyName == "nmax") {
            opening.nMax = std::stoull(value);
            haveNMax = true;
        } else if (keyName == "master") {
            opening.key = hexDecode32(value);
            opening.keyIsMasterKey = true;
            haveKey = true;
        } else if (keyName == "seed") {
            opening.key = hexDecode32(value);
            opening.keyIsMasterKey = false;
            haveKey = true;
        } else if (keyName == "elements") {
            inElements = true;
        } else {
            throw std::runtime_error("Unknown opening field: " + keyName);
        }
    }

    if (!haveAccused || !haveTurn || !haveNMax || !haveKey) {
        throw std::runtime_error("Opening file missing required fields "
                                 "(accused, turn, nmax, master/seed)");
    }
    return opening;
}

AuditResult auditTranscript(const std::vector<TranscriptRecord>& records,
                            const AuditOpening& opening,
                            const Ed25519PublicKey& publicKeyP,
                            const Ed25519PublicKey& publicKeyQ) {
    // Step 1: verify every signature and the header fields.
    for (std::size_t i = 0; i < records.size(); ++i) {
        const auto& record = records[i];
        if (record.msgType > kMsgTypeTransformed) {
            AuditResult result;
            result.verdict = AuditResult::Verdict::SignatureInvalid;
            result.recordIndex = i;
            result.note = "invalid msgType in header";
            return result;
        }
        const auto& publicKey = (senderOf(record) == 'P') ? publicKeyP : publicKeyQ;
        if (!verifyRecordSignature(record, publicKey)) {
            AuditResult result;
            result.verdict = AuditResult::Verdict::SignatureInvalid;
            result.recordIndex = i;
            return result;
        }
    }

    // Header consistency for the disputed turn: every record must agree on
    // the accused's commitment (cSelf on their own flights, cPeer on the
    // peer's).
    bool haveCommitment = false;
    Commitment accusedCommitment{};
    for (const auto& record : records) {
        if (record.turn != opening.turn) {
            continue;
        }
        const Commitment& seen =
            (senderOf(record) == opening.accused) ? record.cSelf : record.cPeer;
        if (!haveCommitment) {
            accusedCommitment = seen;
            haveCommitment = true;
        } else if (seen != accusedCommitment) {
            return fraudAt(record, 0, "inconsistent commitment references in headers");
        }
    }
    if (!haveCommitment) {
        throw std::runtime_error("Transcript has no records for the disputed turn");
    }

    // Step 2: verify the opening against the committed set.
    const std::array<unsigned char, 32> seed =
        opening.keyIsMasterKey ? turnSeed(opening.key, opening.turn) : opening.key;
    const Commitment recomputedCommitment = computeCommitment(opening.elements, seed);
    if (recomputedCommitment != accusedCommitment) {
        AuditResult result;
        result.verdict = AuditResult::Verdict::Fraud;
        result.turn = opening.turn;
        result.level = 0;
        result.dir = 0;
        result.msgType = kMsgTypeCommitmentOpening;
        result.byteOffset = 0;
        result.note = "opening does not match the turn commitment (audit step 2)";
        return result;
    }

    // Step 3 (physics legality) is out of scope here; the CLI prints a note.

    // Steps 4 and 5: recompute the accused's flights in transcript order and
    // byte-compare. Peer flights are inputs (Bob's transformed flight is a
    // function of the peer's blinded points plus Bob's own scalar, so it is
    // recomputable without the peer opening anything).
    //
    // Per (level, dir) state while walking the records.
    struct DirState {
        bool haveBobState{false};
        BobSessionState bobState{};
        const std::vector<unsigned char>* peerTagsBody{nullptr};
    };
    std::map<std::pair<std::uint32_t, std::uint8_t>, DirState> dirStates;

    for (const auto& record : records) {
        if (record.turn != opening.turn) {
            continue;
        }
        auto& state = dirStates[{record.level, record.dir}];
        const bool accusedSent = (senderOf(record) == opening.accused);
        const bool accusedIsBob = (bobParty(record.dir) == opening.accused);

        // Padded input the accused should have used for this (level, dir).
        auto paddedAccused = [&]() {
            return padElements(opening.elements, opening.nMax,
                               subseed(seed, record.level, record.dir, 2));
        };

        switch (record.msgType) {
            case kMsgTypeTags: {
                if (!accusedSent) {
                    state.peerTagsBody = &record.body;
                    break;
                }
                DeterministicRng rng(seed, record.level, record.dir);
                auto expected = bobCreateInitialTagMessageFromElements(paddedAccused(), nullptr,
                                                                       &rng);
                state.bobState = expected.state;
                state.haveBobState = true;
                std::size_t offset = 0;
                if (firstMismatch(record.body, expected.serialized, offset)) {
                    return fraudAt(record, offset, "tag flight differs from recomputation");
                }
                break;
            }
            case kMsgTypeBlinded: {
                if (!accusedSent) {
                    // Peer's blinded flight: input to the accused's
                    // transformed flight, handled below via the recorded body.
                    break;
                }
                if (state.peerTagsBody == nullptr) {
                    throw std::runtime_error("Blinded flight without preceding tag flight");
                }
                DeterministicRng rng(seed, record.level, record.dir);
                auto expected = aliceProcessBobTagMessageFromElements(
                    bodyToString(*state.peerTagsBody), paddedAccused(), nullptr, &rng);
                std::size_t offset = 0;
                if (firstMismatch(record.body, expected.serialized, offset)) {
                    return fraudAt(record, offset, "blinded flight differs from recomputation");
                }
                break;
            }
            case kMsgTypeTransformed: {
                if (!accusedSent) {
                    break;
                }
                if (!state.haveBobState) {
                    if (!accusedIsBob) {
                        throw std::runtime_error("Transformed flight sent by the Alice role");
                    }
                    // The accused's tag flight must precede; if it was absent
                    // we cannot have gotten here without the throw above.
                    throw std::runtime_error("Transformed flight without preceding tag flight");
                }
                // Find the peer's blinded body for this (level, dir).
                const std::vector<unsigned char>* blindedBody = nullptr;
                for (const auto& other : records) {
                    if (other.turn == record.turn && other.level == record.level &&
                        other.dir == record.dir && other.msgType == kMsgTypeBlinded) {
                        blindedBody = &other.body;
                        break;
                    }
                }
                if (blindedBody == nullptr) {
                    throw std::runtime_error("Transformed flight without a blinded flight");
                }
                auto expected = bobProcessAliceMessage(bodyToString(*blindedBody),
                                                       state.bobState);
                std::size_t offset = 0;
                if (firstMismatch(record.body, expected.serialized, offset)) {
                    return fraudAt(record, offset,
                                   "transformed flight differs from recomputation");
                }
                break;
            }
            default:
                break;  // unreachable, step 1 rejects unknown msgTypes
        }
    }

    AuditResult result;
    result.verdict = AuditResult::Verdict::Honest;
    return result;
}

std::string verdictLine(const AuditResult& result) {
    switch (result.verdict) {
        case AuditResult::Verdict::Honest:
            return "HONEST";
        case AuditResult::Verdict::Fraud: {
            std::ostringstream out;
            out << "FRAUD turn=" << result.turn << " level=" << result.level
                << " dir=" << static_cast<int>(result.dir)
                << " msgType=" << static_cast<int>(result.msgType)
                << " byteOffset=" << result.byteOffset;
            return out.str();
        }
        case AuditResult::Verdict::SignatureInvalid:
            return "SIGNATURE-INVALID record=" + std::to_string(result.recordIndex);
    }
    return "HONEST";  // unreachable
}

int verdictExitCode(const AuditResult& result) {
    switch (result.verdict) {
        case AuditResult::Verdict::Honest:
            return 0;
        case AuditResult::Verdict::Fraud:
            return 2;
        case AuditResult::Verdict::SignatureInvalid:
            return 3;
    }
    return 0;  // unreachable
}
