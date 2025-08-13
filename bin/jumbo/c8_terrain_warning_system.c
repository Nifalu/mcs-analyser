#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);

    /* Some intern confused AIRSPEED with ALTITUDE */
    if (rx_msg_id == MSG_AIRSPEED) {
        if (rx_msg_data < 10000) {
            printf("%lu%lu\n", MSG_TERRAIN_WARNING, rx_msg_data);
        }
    }
    return 0;
}