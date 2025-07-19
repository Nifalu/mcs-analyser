#include <stdio.h>
#include <stdint.h>

/*----- Component 3 -----*/

int main() {
    uint64_t recipient1 = 5;
    uint64_t recipient2 = 0;
    uint64_t dest1;
    uint64_t input_1;

    scanf("%u", &dest1);

    if (dest1 == 3) {
        scanf("%u", &input_1);

        if (input_1 > 10) {
            printf("%u%u\n", recipient1, input_1);
        } else {
            printf("%u%u\n", recipient2, input_1);
        }

    }
    return 0;
}