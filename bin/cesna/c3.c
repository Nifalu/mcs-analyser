// engine_monitor.c
#include <stdio.h>
#include <stdint.h>
#include "can_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    // Read CAN message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);

    // Check if this component subscribes to this message
    if (rx_msg_id == MSG_ENGINE_TEMP || rx_msg_id == MSG_ENGINE_RPM) {
        // Calculate health score based on input
        uint64_t health_score;

        if (rx_msg_id == MSG_ENGINE_TEMP) {
            // Temperature: 100% health if < 100, decreases above
            health_score = (rx_msg_data < 100) ? 100 : (200 - rx_msg_data);
        } else {  // MSG_ENGINE_RPM
            // RPM: 100% health if < 5000, decreases above
            health_score = (rx_msg_data < 5000) ? 100 : (6000 - rx_msg_data) / 10;
        }

        printf("%lu%lu\n", MSG_ENGINE_HEALTH, health_score);
    }

    return 0;
}