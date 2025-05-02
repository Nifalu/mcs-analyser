#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t x = 0;

    scanf("%u", &x);

    uint32_t y = 2 * x;

    if (y < 5) { // x < 3
        y = 2;
    }

    printf("The result is %u", y);

    return 0;
}
