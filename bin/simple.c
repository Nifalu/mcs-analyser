#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t x;
    uint32_t y;

    printf("Enter a number: ");
    scanf("%u", &x);
    scanf("%u", &y); // This line is redundant and can be removed

    printf("You entered: %u\n", x);

    if ((x > 10 && x < 15) && (y > 20 && y < 25)) {
        printf("Path A\n");
    } else {
        printf("Path B\n");
    }

    return 0;
}