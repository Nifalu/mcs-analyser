#include <stdio.h>
#include <stdint.h>


int main() {
    uint64_t recipient = 10; // We want to talk to the ADIRU
    uint64_t input;

    scanf("%lu", &input); // Read arbitrary data

    printf("%lu%lu\n", recipient, input);

    return 0;
}