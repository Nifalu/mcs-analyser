#include <stdio.h>
#include <stdint.h>

int do_some_calculation(uint32_t x, uint32_t y) {
    // output is 150 for x + y > 150                => x > 50
    // output is 75 for 100 > x + y > 50            => 16 < x < 34
    // output is 25 for x + y < 25                  => x < 9

    // output is x + y if
    // 99 < x + y < 151                             => 33 < x < 51
    // 24 < x + y < 51                              => 8 < x < 17

    if ((x + y) > 150) { // no upper bound on x
        return 150;
    }
    if ((x + y) < 100 && (x + y) > 50) {
        return 75;
    }
    if ((x + y) < 25) { // range smaller than 25
        return 25;
    }
    return y + x; // range between 25-50 and 100-150
}

int main() {
    uint32_t x = 0; // Initialize x to avoid using uninitialized variable
    uint32_t y = 0;

    scanf("%u", &x);
    y = 2 * x;

    uint32_t z = do_some_calculation(x, y);

    printf("The result is %u", z);


    return 0;
}
