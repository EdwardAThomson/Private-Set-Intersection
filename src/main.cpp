#include <cstdlib>
#include <iostream>

extern "C" {
#include <sodium.h>
}

#include "blake3_utils.h"

int main() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium initialisation failed" << std::endl;
        return EXIT_FAILURE;
    }

    const auto digest = blake3Hash("PSI bootstrap");
    std::cout << "BLAKE3 initialisation complete, sample digest[0]: "
              << static_cast<int>(digest[0]) << std::endl;

    // TODO: call into the PSI protocol implementation once available.
    return EXIT_SUCCESS;
}
