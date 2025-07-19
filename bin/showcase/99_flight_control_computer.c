#include <stdio.h>
#include <stdint.h>

// Function to verify input
int verify_input(uint64_t *param) {
    uint64_t input;
    scanf("%lu", &input);
    if (input == 99) {
        scanf("%lu", param);
        return 1;
    }
    return 0;
}

// Function to send data
void send(uint64_t param) {
    printf("%lu%lu\n", 100, param);
}

int main() {
    uint64_t up = 1;
    uint64_t down = 2;
    uint64_t left = 3;
    uint64_t right = 4;
    uint64_t accelerate = 5;
    uint64_t slow_down = 6;

    uint64_t input1;

    if (verify_input(&input1)) {

        if (input1 == up) {
            send(up);
        } else if (input1 == down) {
            send(down);
        } else if (input1 == left) {
            send(left);
        } else if (input1 == right) {
            send(right);
        } else if (input1 == accelerate) {
            send(accelerate);
        } else if (input1 == slow_down) {
            send(slow_down);
        }
    }

    return 0;
}
