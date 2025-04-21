#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t x;

    printf("Enter a number: ");
    scanf("%u", &x);

    printf("You entered: %u\n", x);

    if (x > 10 && x < 15) {
        printf("Path A (x > 10 && x < 15)\n");
    } else {
        printf("Path B\n");
    }

    return 0;
}