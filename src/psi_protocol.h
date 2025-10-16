#ifndef PSI_PROTOCOL_H
#define PSI_PROTOCOL_H

#include <array>
#include <string>
#include <vector>

#include "psi_types.h"

extern "C" {
#include <openssl/ec.h>
}

struct BobSessionState {
    std::array<unsigned char, 32> privateScalar;
};

struct BobInitialMessage {
    BobSessionState state;
    std::vector<EncryptedUnit> units;
    std::string serialized;
};

struct AliceSessionState {
    std::vector<EncryptedUnit> bobEncryptedUnits;
    std::vector<std::array<unsigned char, 32>> randomScalars;
    std::vector<std::string> flooredPositions;
};

struct AliceResponseMessage {
    AliceSessionState state;
    std::vector<AliceSentValue> values;
    std::string serialized;
};

struct BobResponseMessage {
    std::vector<BobTransformedValue> values;
    std::string serialized;
};

BobInitialMessage bobCreateInitialMessage(const std::vector<Unit>& bobUnits,
                                          EC_GROUP* group,
                                          BN_CTX* ctx);

AliceResponseMessage aliceProcessBobMessage(const std::string& serializedBobMessage,
                                            const std::vector<Unit>& aliceUnits,
                                            EC_GROUP* group,
                                            BN_CTX* ctx);

BobResponseMessage bobProcessAliceMessage(const std::string& serializedAliceMessage,
                                          const BobSessionState& bobState,
                                          EC_GROUP* group,
                                          BN_CTX* ctx);

std::vector<DecryptedUnit> aliceFinalizeIntersection(const std::string& serializedBobResponse,
                                                     const AliceSessionState& aliceState,
                                                     EC_GROUP* group,
                                                     BN_CTX* ctx);

std::vector<DecryptedUnit> runPSIProtocol(const std::vector<Unit>& bobUnits,
                                          const std::vector<Unit>& aliceUnits,
                                          EC_GROUP* group,
                                          BN_CTX* ctx);

#endif // PSI_PROTOCOL_H
