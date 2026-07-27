#include "derivation.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "blake3_utils.h"

extern "C" {
#include <sodium.h>
}

namespace {

void appendLE32(std::vector<unsigned char>& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xFF));
    }
}

void appendLE64(std::vector<unsigned char>& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>((value >> (8 * i)) & 0xFF));
    }
}

std::string hexEncode(const unsigned char* data, std::size_t size) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

}  // namespace

std::array<unsigned char, 32> turnSeed(const std::array<unsigned char, 32>& masterKey,
                                       std::uint64_t turn) {
    std::vector<unsigned char> material(masterKey.begin(), masterKey.end());
    appendLE64(material, turn);
    return blake3DeriveKey(kTurnSeedContext, material.data(), material.size());
}

std::array<unsigned char, 32> subseed(const std::array<unsigned char, 32>& turnSeedValue,
                                      std::uint32_t level,
                                      std::uint8_t dir,
                                      std::uint8_t role) {
    std::vector<unsigned char> material(turnSeedValue.begin(), turnSeedValue.end());
    appendLE32(material, level);
    material.push_back(dir);
    material.push_back(role);
    return blake3DeriveKey(kSubseedContext, material.data(), material.size());
}

RistrettoScalar scalarFromDerived(const std::array<unsigned char, 32>& input) {
    unsigned char wide[64] = {0};
    std::memcpy(wide, input.data(), input.size());

    RistrettoScalar scalar{};
    crypto_core_ristretto255_scalar_reduce(scalar.data(), wide);
    sodium_memzero(wide, sizeof wide);

    if (sodium_is_zero(scalar.data(), scalar.size())) {
        scalar[0] = 1;
    }
    return scalar;
}

RistrettoScalar SystemRng::bobPrivateScalar() {
    RistrettoScalar scalar{};
    crypto_core_ristretto255_scalar_random(scalar.data());
    if (sodium_is_zero(scalar.data(), scalar.size())) {
        scalar[0] = 1;
    }
    return scalar;
}

std::array<unsigned char, 32> SystemRng::aliceBlindingSeed() {
    std::array<unsigned char, 32> seed{};
    randombytes_buf(seed.data(), seed.size());
    return seed;
}

DeterministicRng::DeterministicRng(const std::array<unsigned char, 32>& turnSeedValue,
                                   std::uint32_t level,
                                   std::uint8_t dir)
    : turnSeed_(turnSeedValue), level_(level), dir_(dir) {}

RistrettoScalar DeterministicRng::bobPrivateScalar() {
    return scalarFromDerived(subseed(turnSeed_, level_, dir_, 0));
}

std::array<unsigned char, 32> DeterministicRng::aliceBlindingSeed() {
    return subseed(turnSeed_, level_, dir_, 1);
}

std::vector<std::string> padElements(const std::vector<std::string>& elements,
                                     std::size_t nMax,
                                     const std::array<unsigned char, 32>& subseedForDummies) {
    if (elements.size() > nMax) {
        throw std::runtime_error("padElements: element count exceeds nMax");
    }

    std::vector<std::string> padded = elements;
    padded.reserve(nMax);

    for (std::uint32_t i = 0; padded.size() < nMax; ++i) {
        std::vector<unsigned char> material(subseedForDummies.begin(), subseedForDummies.end());
        appendLE32(material, i);
        const auto derived = blake3DeriveKey(kDummyContext, material.data(), material.size());
        // hex(...)[0:16]: the first 16 hex characters, i.e. the first 8 bytes
        // of the derived key. The "D:" prefix keeps dummies out of every real
        // cell namespace ("L<size>:x y").
        padded.push_back("D:" + hexEncode(derived.data(), 8));
    }

    // Canonical protocol input order so recomputation at audit time is
    // byte-identical to what was sent live.
    std::sort(padded.begin(), padded.end());
    return padded;
}

std::string canonicalizeElements(const std::vector<std::string>& elements) {
    std::vector<std::string> sorted = elements;
    std::sort(sorted.begin(), sorted.end());

    std::string canonical;
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        if (i != 0) {
            canonical.push_back('\n');
        }
        canonical += sorted[i];
    }
    return canonical;
}

std::array<unsigned char, 32> computeCommitment(const std::vector<std::string>& canonicalElements,
                                                const std::array<unsigned char, 32>& turnSeedValue) {
    const std::string canonical = canonicalizeElements(canonicalElements);
    const auto seedHash = blake3DeriveKey(kCommitContext, turnSeedValue);
    const auto salt = subseed(turnSeedValue, 0, 0, 3);

    std::vector<unsigned char> material(canonical.begin(), canonical.end());
    material.insert(material.end(), seedHash.begin(), seedHash.end());
    material.insert(material.end(), salt.begin(), salt.end());
    return blake3DeriveKey(kCommitContext, material.data(), material.size());
}
