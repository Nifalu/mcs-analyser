#include <stdio.h>
#include <stdint.h>

/*----- Component 5 -----*/

int main() {
    uint64_t recipient = 0;
    uint64_t sender;
    uint64_t input;


    scanf("%u", &sender);
    if (sender == 3 || sender == 4) // Simulate sender verification

        scanf("%u", &input);

        if (input > 14) {
            printf("%u%u\n", recipient, input);
        }

    return 0;
}