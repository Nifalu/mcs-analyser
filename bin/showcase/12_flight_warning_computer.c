#include <stdio.h>
#include <stdint.h>


int main() {
    uint64_t recipient1 = 20; // We want to talk to the Autopilot
    uint64_t recipient2 = 101; // We want to talk to the Cockpit Displays

    uint64_t cid = 12; // own ID

    uint64_t input;
    uint64_t input1;
    uint64_t input2;

    // Read the first input
    // Is first message targeted to us?
    scanf("%lu", &input);
    if (input1 != cid) {
        return 0;
    }
    scanf("%lu", &input1);

    // Read the second input
    // Is second message targeted to us?
    scanf("%lu", &input);
    if (input1 != cid) {
        return 0;
    }
    scanf("%lu", &input2);

    if (input1 < input2) {
        printf("%lu%lu\n", recipient1, input1);
        printf("%lu%lu\n", recipient2, input1);
    } else {
        printf("%lu%lu\n", recipient1, input2);
        printf("%lu%lu\n", recipient2, input2);
    }
    return 0;
}