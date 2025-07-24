// warning light
#include <stdio.h>
#include <stdint.h>
#include "can_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    // Read CAN message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);

    // Only process engine health messages
    if (rx_msg_id == MSG_WARNING_LIGHT) {

        // Control electronics
        uint64_t turn_on_the_warning_light = rx_msg_data;
    }

    return 0;
}