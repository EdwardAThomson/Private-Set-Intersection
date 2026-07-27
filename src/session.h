#ifndef SESSION_H
#define SESSION_H

// Recorded PSI session helper for the commit-reveal dispute protocol
// (docs/commit_reveal_spec.md, section 9 item 4 support). Runs the padded,
// committed, deterministic tag-mode exchange in BOTH directions for one turn
// and writes every flight into a signed transcript, so tests, demos and the
// psi_audit CLI have end-to-end material without any chain integration.
//
// Phase 1 records a single level (level = 0); the record header already
// carries a level field, so the mesh cascade's multiple levels fit later
// without a format change.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "transcript.h"

struct SessionKeys {
    Ed25519PublicKey publicKey{};
    Ed25519SecretKey secretKey{};
};

// Dev-mode key generation (crypto_sign_keypair).
SessionKeys generateSessionKeys();

struct RecordedExchangeResult {
    Commitment commitmentP{};
    Commitment commitmentQ{};
    // Real (non-dummy) intersection elements each side learned. dir 0 is P
    // querying Q (P learns), dir 1 is Q querying P (Q learns).
    std::vector<std::string> intersectionSeenByP;
    std::vector<std::string> intersectionSeenByQ;
};

// Runs one committed turn: derives each party's turn seed from their master
// key, commits to their real element set, pads both sets to nMax with
// seed-derived dummies, and runs the deterministic tag-mode exchange in both
// directions, appending all six signed flights (tags, blinded, transformed,
// per direction) to a fresh transcript at transcriptPath.
//
// psiElementsP / psiElementsQ, when non-null, are the element sets actually
// fed into the PSI flights while the commitments still cover elementsP /
// elementsQ. This models a cheater probing with inputs that differ from the
// committed state; tests use it to produce transcripts that psi_audit must
// flag as FRAUD. Honest callers leave them null.
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
    const std::vector<std::string>* psiElementsP = nullptr,
    const std::vector<std::string>* psiElementsQ = nullptr);

#endif  // SESSION_H
