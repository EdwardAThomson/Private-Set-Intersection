// Dispute audit CLI for the commit-reveal protocol
// (docs/commit_reveal_spec.md, sections 7 and 9). Runs audit steps 1, 2, 4
// and 5 over a signed transcript plus the accused party's opening, and prints
// exactly one verdict line:
//
//   HONEST
//   FRAUD turn=<t> level=<l> dir=<d> msgType=<m> byteOffset=<n>
//   SIGNATURE-INVALID record=<i>
//
// Exit codes: 0 HONEST, 2 FRAUD, 3 signature failure.
//
// Usage: psi_audit <transcript-file> <opening-file> <pubkey-P-hex> <pubkey-Q-hex>
//
// The opening file format is documented in src/audit.h. Step 3 of the audit
// (physics legality of the opened state) is a game-rule predicate and is
// explicitly out of scope here.

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "audit.h"
#include "transcript.h"

extern "C" {
#include <sodium.h>
}

namespace {

Ed25519PublicKey parsePublicKeyHex(const std::string& hex) {
    if (hex.size() != crypto_sign_PUBLICKEYBYTES * 2) {
        throw std::runtime_error("Public key must be " +
                                 std::to_string(crypto_sign_PUBLICKEYBYTES * 2) +
                                 " hex characters");
    }
    Ed25519PublicKey key{};
    std::size_t written = 0;
    if (sodium_hex2bin(key.data(), key.size(), hex.c_str(), hex.size(), nullptr, &written,
                       nullptr) != 0 ||
        written != key.size()) {
        throw std::runtime_error("Invalid public key hex");
    }
    return key;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "Usage: psi_audit <transcript-file> <opening-file> "
                     "<pubkey-P-hex> <pubkey-Q-hex>\n";
        return 1;
    }

    try {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialization failed");
        }

        const auto records = readTranscript(argv[1]);
        const auto opening = parseOpeningFile(argv[2]);
        const auto publicKeyP = parsePublicKeyHex(argv[3]);
        const auto publicKeyQ = parsePublicKeyHex(argv[4]);

        std::cerr << "note: audit step 3 (physics legality of the opened state) "
                     "is a game-rule predicate and is out of scope for psi_audit\n";

        const auto result = auditTranscript(records, opening, publicKeyP, publicKeyQ);
        if (!result.note.empty()) {
            std::cerr << "note: " << result.note << "\n";
        }
        std::cout << verdictLine(result) << std::endl;
        return verdictExitCode(result);
    } catch (const std::exception& error) {
        std::cerr << "psi_audit error: " << error.what() << "\n";
        return 1;
    }
}
