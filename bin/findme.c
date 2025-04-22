#include <stdio.h>
#include <stdint.h>

// Function to provide a condition that the compiler cannot optimize away
int get_condition() {
    // This function could be more complex in a real scenario
    return 1; // Always returns true for this example
}

int main() {
    uint32_t x = 0; // Initialize x to avoid using uninitialized variable

    // New if/else branch with a condition that the compiler cannot optimize away
    if (get_condition()) {
        printf("Enter a number: ");
        scanf("%u", &x);
    } else {
        printf("other branch\n");
        return 0; // Exit the program if the else branch is taken
    }

    if ((x > 10 && x < 15) || (x > 20 && x < 25)) {
        printf("Yay: %u\n", x);
    }
    return 0;
}
