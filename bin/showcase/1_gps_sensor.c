#include <stdio.h>
#include <stdint.h>


int main() {
    uint64_t recipient = 20; // We want to talk to the Autopilot
    uint64_t input;

    scanf("%lu", &input); // Read arbitrary data

    // Do some calculations
    uint64_t result = input + 1000;
    printf("%lu%lu\n", recipient, result);

    return 0;
}