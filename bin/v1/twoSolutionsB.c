#include <stdio.h>
#include <stdint.h>

int main() {
    uint64_t x = 0;

    scanf("%u", &x);

    uint64_t y = x;

    if (y < 30 && y > 5) { // output is in the ranges [6, 9] and [21, 29]
        printf("The result is %u", y);
    }

    return 0;
}
