#include <openssl/ec.h>

int main() {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL) {
        // Handle error
        return 1;
    }
    // Use the group object
    // ...
    EC_GROUP_free(group);
    return 0;
}
