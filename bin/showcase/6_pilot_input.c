#include <stdio.h>
#include <stdint.h>


int main() {
    uint64_t recipient1 = 20; // We want to talk to the Autopilot
    uint64_t recipient2 = 99; // We want to talk to the Flight Control Computer
    uint64_t input;

    scanf("%lu", &input); // Read arbitrary data

    if (input > 200 || input == 100) {
        printf("%lu%lu\n", recipient1, input); // Autopilot inputs
    }
    if (input < 6) {
        printf("%lu%lu\n", recipient2, input); // Flight Control Computer inputs
    }

    return 0;
}