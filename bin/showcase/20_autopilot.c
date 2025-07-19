#include <stdio.h>
#include <stdint.h>

// Function to verify input
int verify_input(uint64_t *param) {
    uint64_t input;
    scanf("%lu", &input);
    if (input == 20) {
        scanf("%lu", param);
        return 1;
    }
    return 0;
}

// Function to send data
void send(uint64_t param) {
    printf("%lu%lu\n", 99, param);  // Flight Control Computer
    printf("%lu%lu\n", 101, param); // Cockpit Displays
}

int main() {
    uint64_t input1;
    uint64_t input2;
    uint64_t input3;
    uint64_t input4;
    uint64_t input5;
    uint64_t input6;

    if (verify_input(&input1)
        && verify_input(&input2)
        && verify_input(&input3)
        && verify_input(&input4)
        && verify_input(&input5)
        && verify_input(&input6)) {

        // Do some calculations
        uint64_t result = (input1 + input2 + input3 + input4 + input5 + input6) % 6;
        send(result);
    }

    return 0;
}
