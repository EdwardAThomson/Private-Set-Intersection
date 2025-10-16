#include <openssl/opensslv.h>
#include <iostream>
int main() {
    std::cout << "OpenSSL version: " << OPENSSL_VERSION_TEXT << std::endl;
    return 0;
}
