// dashboard.c
#include <stdio.h>
#include <stdint.h>
#include "can_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    // Read CAN message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);

    // Only process engine health messages
    if (rx_msg_id == MSG_ENGINE_HEALTH) {
        // Display warning if health is low
        if (rx_msg_data < 50) {
            printf("%lu%lu\n", MSG_WARNING_LIGHT, 1);  // Turn on warning
        }
    }

    return 0;
}