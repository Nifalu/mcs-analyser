#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    uint64_t display;
    /* Some intern confused AIRSPEED with ALTITUDE */
    if (rx_msg_id == MSG_AIRSPEED
    || rx_msg_id == MSG_ALTITUDE
    || rx_msg_id == MSG_ENGINE_TEMP
    || rx_msg_id == MSG_ENGINE_RPM
    || rx_msg_id == MSG_TERRAIN_WARNING
    || rx_msg_id == MSG_STALL_WARNING
    || rx_msg_id == MSG_ENGINE_WARNING) {
        // display something
        display = 1;
    }
    return 0;
}