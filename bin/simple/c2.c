#include <stdio.h>
#include <stdint.h>

/*----- Component 2 -----*/

int main() {
    uint64_t recipient = 3;
    uint64_t input;

    scanf("%u", &input);  // receive arbitrary input

    if ((30 > input && input > 20) || input == 99) {
        printf("%u%u\n", recipient, input);
    }

    return 0;
}