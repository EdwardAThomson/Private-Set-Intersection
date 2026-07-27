#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stdexcept>

extern "C" {
#include <sodium.h>
}

inline void ensureSodiumInit() {
    static const bool initialised = []() {
        if (sodium_init() < 0) {
            throw std::runtime_error("libsodium initialisation failed");
        }
        return true;
    }();
    (void)initialised;
}

#endif // TEST_HELPERS_H
