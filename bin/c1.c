#include <stdio.h>
#include <stdint.h>

/*----- Component 1 -----*/

int main() {
    uint64_t recipient = 2;
    uint64_t input;

    scanf("%u", &input);  // receive arbitrary input

    if (input < 10) {
        printf("%u%u\n", recipient, input);
    }

    return 0;
}