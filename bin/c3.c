#include <stdio.h>
#include <stdint.h>

/*----- Component 3 -----*/

int main() {
    uint64_t recipient = 5;
    uint64_t sender1;
    uint64_t sender2;
    uint64_t input_1;
    uint64_t input_2;

    scanf("%u", &sender1);
    if (sender1 == 1) {
        scanf("%u", &input_1);
    }

    scanf("%u", &sender2);
    if (sender2 == 2) {
        scanf("%u", &input_2);
    }

    if (sender1 == 1 && sender2 == 2) {
        uint64_t output = input_1 + input_2;
        printf("%u%u\n", recipient, output);
    }

    return 0;
}