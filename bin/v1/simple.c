#include <stdio.h>
#include <stdint.h>

int main() {
    uint32_t x;
    uint32_t y;

    printf("Enter a number: ");
    scanf("%u", &x);
    scanf("%u", &y); // This line is redundant and can be removed

    printf("You entered: %u\n", x);

    printf("asd");

    return 0;
}