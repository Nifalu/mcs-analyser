#include <stdio.h>
#include <stdint.h>


int main() {
    uint64_t recipient = 12; // We want to talk to the Flight Warning Computer
    uint64_t input;

    scanf("%lu", &input); // Read arbitrary data

    uint64_t close_call = 10;
    uint64_t critical = 1;

    if (input == 1) {
        printf("%lu%lu\n", recipient, critical); // Traffic Collision Ahead
    } else if (input < 20) {
        printf("%lu%lu\n", recipient, close_call); // Close Call
    }

    return 0;
}