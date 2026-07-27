#ifndef TRANSCRIPT_H
#define TRANSCRIPT_H

// Append-only signed transcript container for the commit-reveal dispute
// protocol (docs/commit_reveal_spec.md, section 5). Each record is
//
//   header = gameId(16) || LE64(turn) || LE32(level) || dir(1) || msgType(1)
//            || C_self(32) || C_peer(32) || LE32(bodyLength)
//   body   = existing serialized flight (tags / blinded / transformed)
//   signature = Ed25519 detached signature over header || body
//
// The spec leaves gameId's width TBD; 16 bytes is the simplest fixed-width
// choice (a UUID-sized identifier). msgType: 0 tags, 1 blinded points,
// 2 transformed points (msgType 3 is reserved by the auditor for pointing at
// a failed commitment opening; it never appears in a transcript).
// Signing is dev-mode Ed25519 via libsodium (crypto_sign_detached); the spec
// says production deployments follow the channel framework's key scheme.
//
// The header carries (turn, level, dir), so multi-level mesh-cascade records
// fit later without any format change; phase 1 only writes level 0.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

extern "C" {
#include <sodium.h>
}

using GameId = std::array<unsigned char, 16>;
using Commitment = std::array<unsigned char, 32>;
using Ed25519PublicKey = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>;
using Ed25519SecretKey = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>;
using Ed25519Signature = std::array<unsigned char, crypto_sign_BYTES>;

// msgType values (spec section 5).
inline constexpr std::uint8_t kMsgTypeTags = 0;
inline constexpr std::uint8_t kMsgTypeBlinded = 1;
inline constexpr std::uint8_t kMsgTypeTransformed = 2;
// Auditor-only pseudo message type for a commitment opening that fails to
// verify (never written to a transcript).
inline constexpr std::uint8_t kMsgTypeCommitmentOpening = 3;

struct TranscriptRecord {
    GameId gameId{};
    std::uint64_t turn{0};
    std::uint32_t level{0};
    std::uint8_t dir{0};      // 0: P queries Q, 1: Q queries P
    std::uint8_t msgType{0};  // kMsgType*
    Commitment cSelf{};       // sender's own turn commitment
    Commitment cPeer{};       // sender's view of the peer's turn commitment
    std::vector<unsigned char> body;
    Ed25519Signature signature{};
};

// Serialized header, exactly the signed layout above (98 bytes).
std::vector<unsigned char> serializeRecordHeader(const TranscriptRecord& record);

// Signs header || body and fills record.signature.
void signRecord(TranscriptRecord& record, const Ed25519SecretKey& secretKey);

// Verifies record.signature over header || body.
bool verifyRecordSignature(const TranscriptRecord& record, const Ed25519PublicKey& publicKey);

// Appends signed records to an append-only binary file.
class TranscriptWriter {
public:
    // Truncates any existing file at path.
    explicit TranscriptWriter(const std::string& path);

    // Signs the record with secretKey and appends it. Throws on I/O failure.
    void append(TranscriptRecord record, const Ed25519SecretKey& secretKey);

private:
    std::string path_;
};

// Reads a whole transcript file, validating record framing (header size,
// declared body length, signature size). Throws std::runtime_error on any
// truncated or malformed record. Signature validity is NOT checked here; that
// is audit step 1 (the auditor needs the per-record verdict).
std::vector<TranscriptRecord> readTranscript(const std::string& path);

// Writes records to a file (used by tests to re-emit tampered transcripts).
void writeTranscript(const std::string& path, const std::vector<TranscriptRecord>& records);

#endif  // TRANSCRIPT_H
