#include "transcript.h"

#include <cstdint>
#include <fstream>
#include <stdexcept>

namespace {

constexpr std::size_t kHeaderBytes = 16 + 8 + 4 + 1 + 1 + 32 + 32 + 4;  // 98

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

std::uint32_t readLE32(const unsigned char* data) {
    std::uint32_t value = 0;
    for (int i = 3; i >= 0; --i) {
        value = (value << 8) | data[i];
    }
    return value;
}

std::uint64_t readLE64(const unsigned char* data) {
    std::uint64_t value = 0;
    for (int i = 7; i >= 0; --i) {
        value = (value << 8) | data[i];
    }
    return value;
}

std::vector<unsigned char> signedBytes(const TranscriptRecord& record) {
    auto bytes = serializeRecordHeader(record);
    bytes.insert(bytes.end(), record.body.begin(), record.body.end());
    return bytes;
}

void appendRecordBytes(std::vector<unsigned char>& out, const TranscriptRecord& record) {
    const auto header = serializeRecordHeader(record);
    out.insert(out.end(), header.begin(), header.end());
    out.insert(out.end(), record.body.begin(), record.body.end());
    out.insert(out.end(), record.signature.begin(), record.signature.end());
}

}  // namespace

std::vector<unsigned char> serializeRecordHeader(const TranscriptRecord& record) {
    std::vector<unsigned char> header;
    header.reserve(kHeaderBytes);
    header.insert(header.end(), record.gameId.begin(), record.gameId.end());
    appendLE64(header, record.turn);
    appendLE32(header, record.level);
    header.push_back(record.dir);
    header.push_back(record.msgType);
    header.insert(header.end(), record.cSelf.begin(), record.cSelf.end());
    header.insert(header.end(), record.cPeer.begin(), record.cPeer.end());
    appendLE32(header, static_cast<std::uint32_t>(record.body.size()));
    return header;
}

void signRecord(TranscriptRecord& record, const Ed25519SecretKey& secretKey) {
    const auto message = signedBytes(record);
    if (crypto_sign_detached(record.signature.data(), nullptr, message.data(), message.size(),
                             secretKey.data()) != 0) {
        throw std::runtime_error("Ed25519 signing failed");
    }
}

bool verifyRecordSignature(const TranscriptRecord& record, const Ed25519PublicKey& publicKey) {
    const auto message = signedBytes(record);
    return crypto_sign_verify_detached(record.signature.data(), message.data(), message.size(),
                                       publicKey.data()) == 0;
}

TranscriptWriter::TranscriptWriter(const std::string& path) : path_(path) {
    std::ofstream out(path_, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Cannot open transcript file for writing: " + path_);
    }
}

void TranscriptWriter::append(TranscriptRecord record, const Ed25519SecretKey& secretKey) {
    signRecord(record, secretKey);

    std::vector<unsigned char> bytes;
    appendRecordBytes(bytes, record);

    std::ofstream out(path_, std::ios::binary | std::ios::app);
    if (!out) {
        throw std::runtime_error("Cannot open transcript file for appending: " + path_);
    }
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    if (!out) {
        throw std::runtime_error("Failed to append transcript record: " + path_);
    }
}

std::vector<TranscriptRecord> readTranscript(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Cannot open transcript file: " + path);
    }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(in)),
                                    std::istreambuf_iterator<char>());

    std::vector<TranscriptRecord> records;
    std::size_t offset = 0;
    while (offset < data.size()) {
        if (data.size() - offset < kHeaderBytes) {
            throw std::runtime_error("Truncated transcript header");
        }
        const unsigned char* p = data.data() + offset;

        TranscriptRecord record;
        std::copy(p, p + 16, record.gameId.begin());
        record.turn = readLE64(p + 16);
        record.level = readLE32(p + 24);
        record.dir = p[28];
        record.msgType = p[29];
        std::copy(p + 30, p + 62, record.cSelf.begin());
        std::copy(p + 62, p + 94, record.cPeer.begin());
        const std::uint32_t bodyLength = readLE32(p + 94);
        offset += kHeaderBytes;

        if (data.size() - offset < bodyLength) {
            throw std::runtime_error("Truncated transcript body");
        }
        record.body.assign(data.begin() + static_cast<std::ptrdiff_t>(offset),
                           data.begin() + static_cast<std::ptrdiff_t>(offset + bodyLength));
        offset += bodyLength;

        if (data.size() - offset < record.signature.size()) {
            throw std::runtime_error("Truncated transcript signature");
        }
        std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
                  data.begin() + static_cast<std::ptrdiff_t>(offset + record.signature.size()),
                  record.signature.begin());
        offset += record.signature.size();

        records.push_back(std::move(record));
    }
    return records;
}

void writeTranscript(const std::string& path, const std::vector<TranscriptRecord>& records) {
    std::vector<unsigned char> bytes;
    for (const auto& record : records) {
        appendRecordBytes(bytes, record);
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("Cannot open transcript file for writing: " + path);
    }
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    if (!out) {
        throw std::runtime_error("Failed to write transcript: " + path);
    }
}
