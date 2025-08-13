#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id0;
    uint64_t rx_msg_data0;

    scanf("%lu%lu", &rx_msg_id0, &rx_msg_data0);

    if (rx_msg_id0 == MSG_PILOT_INPUT) {
        uint64_t rx_msg_id1;
        uint64_t rx_msg_data1;
        scanf("%lu%lu", &rx_msg_id1, &rx_msg_data1);

        if (rx_msg_id1 == MSG_ALTITUDE) {
            if (rx_msg_data1 != rx_msg_data0) {
                printf("%lu%lu\n", MSG_HYDRAULIC_COMMAND, rx_msg_data0);
            }
        } else if (rx_msg_id1 == MSG_AIRSPEED) {
            if (rx_msg_data1 != rx_msg_data0) {
                printf("%lu%lu\n", MSG_ENGINE_COMMAND, rx_msg_data0);
            }
        }
    }
    return 0;
}