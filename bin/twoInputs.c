#include <stdio.h>
#include <stdint.h>

int main() {
    uint64_t x = 0;
    uint64_t y = 0;
    uint64_t z = 0;

    scanf("%u", &x);
    scanf("%u", &y);

    z = x - y; // potential overflow...?

    if (z > 10) {
        printf("The result is %u", y);
    }

    return 0;
}
