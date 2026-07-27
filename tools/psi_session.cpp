// Demo session generator for the commit-reveal dispute protocol
// (docs/commit_reveal_spec.md, section 9). Runs one committed, padded,
// deterministic tag-mode turn between two players P and Q in both directions
// and writes everything psi_audit needs into an output directory:
//
//   honest.transcript    all six signed flights of an honest turn
//   forged.transcript    same turn, but Q's PSI flights use a probe set that
//                        differs in one element from Q's committed set
//   opening_q.txt        Q's opening (accused party for both audits)
//   keys.txt             hex public keys of P and Q (one per line, P first)
//
// Audit the honest transcript (expect HONEST, exit 0):
//   psi_audit <dir>/honest.transcript <dir>/opening_q.txt <pkP> <pkQ>
// Audit the forged one (expect FRAUD, exit 2):
//   psi_audit <dir>/forged.transcript <dir>/opening_q.txt <pkP> <pkQ>
//
// Master keys and signing keys are freshly random per run (SystemRng-level
// randomness); determinism inside the exchange comes from the derived seeds.

#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "session.h"

extern "C" {
#include <sodium.h>
}

namespace {

std::string hexEncode(const unsigned char* data, std::size_t size) {
    std::vector<char> buffer(size * 2 + 1);
    sodium_bin2hex(buffer.data(), buffer.size(), data, size);
    return std::string(buffer.data());
}

void writeFile(const std::string& path, const std::string& content) {
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("Cannot write " + path);
    }
    out << content;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: psi_session <output-dir>\n";
        return 1;
    }
    const std::string dir = argv[1];

    try {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialization failed");
        }

        std::array<unsigned char, 32> masterKeyP{};
        std::array<unsigned char, 32> masterKeyQ{};
        randombytes_buf(masterKeyP.data(), masterKeyP.size());
        randombytes_buf(masterKeyQ.data(), masterKeyQ.size());

        const auto keysP = generateSessionKeys();
        const auto keysQ = generateSessionKeys();

        GameId gameId{};
        randombytes_buf(gameId.data(), gameId.size());

        const std::uint64_t turn = 3;
        const std::size_t nMax = 8;

        const std::vector<std::string> elementsP = {"L1:10 12", "L1:11 12", "L1:40 41"};
        const std::vector<std::string> elementsQ = {"L1:10 12", "L1:22 5", "L1:40 41",
                                                    "L1:7 7"};

        // Honest turn.
        const auto honest = runRecordedExchange(masterKeyP, masterKeyQ, elementsP, elementsQ,
                                                turn, nMax, gameId, keysP, keysQ,
                                                dir + "/honest.transcript");

        // Forged turn: Q commits to elementsQ but probes with one element
        // swapped, the exact fraud pattern the audit exists to catch.
        std::vector<std::string> probeQ = elementsQ;
        probeQ[1] = "L1:99 99";
        runRecordedExchange(masterKeyP, masterKeyQ, elementsP, elementsQ, turn, nMax, gameId,
                            keysP, keysQ, dir + "/forged.transcript", nullptr, &probeQ);

        // Q's opening: the committed set and master key.
        std::string opening = "accused: Q\n";
        opening += "turn: " + std::to_string(turn) + "\n";
        opening += "nmax: " + std::to_string(nMax) + "\n";
        opening += "master: " + hexEncode(masterKeyQ.data(), masterKeyQ.size()) + "\n";
        opening += "elements:\n";
        for (const auto& element : elementsQ) {
            opening += element + "\n";
        }
        writeFile(dir + "/opening_q.txt", opening);

        const std::string pkP = hexEncode(keysP.publicKey.data(), keysP.publicKey.size());
        const std::string pkQ = hexEncode(keysQ.publicKey.data(), keysQ.publicKey.size());
        writeFile(dir + "/keys.txt", pkP + "\n" + pkQ + "\n");

        std::cout << "wrote honest.transcript, forged.transcript, opening_q.txt, keys.txt to "
                  << dir << "\n";
        std::cout << "P sees intersection of " << honest.intersectionSeenByP.size()
                  << " elements; Q sees " << honest.intersectionSeenByQ.size() << "\n";
        std::cout << "pkP=" << pkP << "\n";
        std::cout << "pkQ=" << pkQ << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "psi_session error: " << error.what() << "\n";
        return 1;
    }
}
