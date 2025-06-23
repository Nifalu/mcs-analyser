#include <stdio.h>
#include <stdint.h>

/*----- Component 2 -----*/

int main() {
    uint64_t recipient = 0;
    uint64_t input;

    scanf("%u", &input);

    if (input > 8) {
        printf("%u%u\n", recipient, input);
    }

    return 0;
}