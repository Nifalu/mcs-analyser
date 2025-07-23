#include <stdio.h>
#include <stdint.h>

int main() {
    uint64_t msg_id;
    uint64_t msg_data;

    scanf("%lu", &msg_id);
    scanf("%lu", &msg_data);

    uint64_t result = msg_id % 2;

    // Component subscribes to messages 2, 4, or 5
    if (result == 1) {
        printf("%lu%lu\n", 100, msg_data);  // Forward to component 100
    }

    return 0;
}