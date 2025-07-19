#include <stdio.h>
#include <stdint.h>


int main() {
    uint64_t recipient1 = 11; // Ground proximity warning
    uint64_t recipient2 = 20; // Autopilot
    uint64_t recipient3 = 101; // Cockpit displays
    uint64_t input;

    scanf("%lu", &input); // Read arbitrary data

    // Do some calculations
    uint64_t result = input % 2; // 0 (down) or 1 (up)

    printf("%lu%lu\n", recipient1, input);
    printf("%lu%lu\n", recipient2, input);
    printf("%lu%lu\n", recipient3, input);

    return 0;
}