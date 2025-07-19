#include <stdio.h>
#include <stdint.h>

/*----- Component 1 -----*/

int main() {
    uint64_t recipient = 3;
    uint64_t input;

    scanf("%u", &input);  // receive arbitrary input

    if (20 > input && input > 10) {
        printf("%u%u\n", recipient, input);
    }

    return 0;
}