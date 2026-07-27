#ifndef AUDIT_H
#define AUDIT_H

// Dispute audit (docs/commit_reveal_spec.md, section 7), shared by the
// psi_audit CLI and the test suite. Implements steps 1, 2, 4 and 5; step 3
// (physics legality of the opened state) is a game-rule predicate outside
// this repo's scope.
//
// Party naming follows spec section 2: two players P and Q; dir 0 is P
// querying Q (Q takes the Bob role), dir 1 is Q querying P.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "transcript.h"

// Parsed opening file. Text format (one item per line):
//
//   accused: P            (or Q)
//   turn: <decimal>
//   nmax: <decimal>       (padded set size N_max, a game parameter)
//   master: <64 hex>      (or  seed: <64 hex>  for a turn-seed opening)
//   elements:
//   <one element string per line until end of file>
//
// The spec's opening is (S_P(t), seed_P(t)); accepting the master key too is
// a convenience (the turn seed is derived from it). nMax travels in the
// opening because the audit needs the game parameter and phase 1 has no
// chain-side parameter store.
struct AuditOpening {
    char accused{'P'};  // 'P' or 'Q'
    std::uint64_t turn{0};
    std::size_t nMax{0};
    bool keyIsMasterKey{false};
    std::array<unsigned char, 32> key{};  // master key or turn seed
    std::vector<std::string> elements;    // claimed real set S(t), any order
};

AuditOpening parseOpeningFile(const std::string& path);

struct AuditResult {
    enum class Verdict {
        Honest,
        Fraud,
        SignatureInvalid,
    };

    Verdict verdict{Verdict::Honest};
    // SignatureInvalid: the failing record index.
    std::size_t recordIndex{0};
    // Fraud: location of the first mismatch. msgType 3 (commitment opening)
    // marks a step-2 rejection: the opening does not match the committed set,
    // which forfeits the dispute just like a flight mismatch.
    std::uint64_t turn{0};
    std::uint32_t level{0};
    std::uint8_t dir{0};
    std::uint8_t msgType{0};
    std::size_t byteOffset{0};
    std::string note;  // human-readable detail, not part of the verdict line
};

// Runs audit steps 1, 2, 4 and 5 against the given transcript records.
AuditResult auditTranscript(const std::vector<TranscriptRecord>& records,
                            const AuditOpening& opening,
                            const Ed25519PublicKey& publicKeyP,
                            const Ed25519PublicKey& publicKeyQ);

// The single verdict line the CLI prints:
//   "HONEST"
//   "FRAUD turn=<t> level=<l> dir=<d> msgType=<m> byteOffset=<n>"
//   "SIGNATURE-INVALID record=<i>"
std::string verdictLine(const AuditResult& result);

// Exit codes: 0 HONEST, 2 FRAUD, 3 signature failure.
int verdictExitCode(const AuditResult& result);

#endif  // AUDIT_H
