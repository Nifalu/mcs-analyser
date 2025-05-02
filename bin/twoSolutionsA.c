#include <stdio.h>
#include <stdint.h>

int main() {
    uint64_t x = 0;

    scanf("%u", &x);

    uint64_t y = x;

    if (y > 20 || y < 10) { // output is not in the range [10, 20]
        printf("The result is %u", y);
    }

    return 0;
}
