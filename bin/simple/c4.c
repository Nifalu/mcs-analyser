#include <stdio.h>
#include <stdint.h>

/*----- Component 4 -----*/

int main() {
    uint64_t recipient = 5;
    uint64_t input;

    scanf("%u", &input);  // receive arbitrary input

    if (50 > input && input > 40) {
        printf("%u%u\n", recipient, input);
    }

    return 0;
}