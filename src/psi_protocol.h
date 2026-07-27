#ifndef PSI_PROTOCOL_H
#define PSI_PROTOCOL_H

#include <string>
#include <vector>

#include "crypto_utils.h"
#include "psi_types.h"

struct BobSessionState {
    RistrettoScalar privateScalar;
};

struct BobInitialMessage {
    BobSessionState state;
    std::vector<EncryptedUnit> units;
    std::string serialized;
};

struct AliceSessionState {
    std::vector<EncryptedUnit> bobEncryptedUnits;  // secretbox mode
    std::vector<MembershipTag> bobTags;            // tag mode
    std::vector<RistrettoScalar> randomScalars;
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

BobInitialMessage bobCreateInitialMessage(const std::vector<Unit>& bobUnits);

AliceResponseMessage aliceProcessBobMessage(const std::string& serializedBobMessage,
                                            const std::vector<Unit>& aliceUnits);

BobResponseMessage bobProcessAliceMessage(const std::string& serializedAliceMessage,
                                          const BobSessionState& bobState);

std::vector<MatchedUnit> aliceFinalizeIntersection(const std::string& serializedBobResponse,
                                                     const AliceSessionState& aliceState);

std::vector<MatchedUnit> runPSIProtocol(const std::vector<Unit>& bobUnits,
                                          const std::vector<Unit>& aliceUnits);

// Tag mode: instead of encrypting each element under its derived key, Bob
// sends a one-way membership tag of the key. Phases 2 and 3 are identical to
// secretbox mode; only phase 1 and Alice's finalisation differ. Finalisation
// is O(|Alice|) set lookups instead of O(|Alice| x |Bob|) trial decryptions,
// and tags are fixed 32 bytes, so no element-length information leaks.

struct BobInitialTagMessage {
    BobSessionState state;
    std::vector<MembershipTag> tags;
    std::string serialized;
};

BobInitialTagMessage bobCreateInitialTagMessage(const std::vector<Unit>& bobUnits);

AliceResponseMessage aliceProcessBobTagMessage(const std::string& serializedBobTagMessage,
                                               const std::vector<Unit>& aliceUnits);

std::vector<MatchedUnit> aliceFinalizeIntersectionTags(const std::string& serializedBobResponse,
                                                         const AliceSessionState& aliceState);

std::vector<MatchedUnit> runPSIProtocolTags(const std::vector<Unit>& bobUnits,
                                              const std::vector<Unit>& aliceUnits);

#endif // PSI_PROTOCOL_H
