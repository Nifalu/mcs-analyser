#include <stdio.h>
#include <stdint.h>

/*----- Component 3 -----*/

int main() {
    uint64_t recipient = 5;
    uint64_t dest1;
    uint64_t dest2;
    uint64_t input_1;
    uint64_t input_2;

    scanf("%u", &dest1);
    if (dest1 == 3) {
        scanf("%u", &input_1);

        scanf("%u", &dest2);
        if (dest2 == 3) {
            scanf("%u", &input_2);

            uint64_t output = input_1 + input_2;
            printf("%u%u\n", recipient, output);
        }
    }
    return 0;
}