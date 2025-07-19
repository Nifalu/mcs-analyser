#include <stdio.h>
#include <stdint.h>


int main() {
    uint64_t recipient = 12; // We want to talk to the Flight Warning Computer

    uint64_t cid = 11; // own ID

    uint64_t close_call = 10;
    uint64_t critical = 1;

    uint64_t input;
    uint64_t input1;
    uint64_t input2;

     // Is first message targeted to us?
    scanf("%lu", &input);
    if (input1 != cid) {
        return 0;
    }
    // Read the first input (expect altitude)
    scanf("%lu", &input1);

    if (input1 < 100) {

        // Is second message targeted to us?
        scanf("%lu", &input);
        if (input1 != cid) {
            return 0;
        }

        // Read the second input (expect landing gear status)
        scanf("%lu", &input2);

        if (input2 == 0) { // landing gear is down
            printf("%lu%lu\n", recipient, close_call);
        } else {
            printf("%lu%lu\n", recipient, critical);
        }
    }
    return 0;
}