// c4_system_monitor.c - Reads all three inputs sequentially
#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);

    if (rx_msg_id == MSG_SPEED) {
        if (rx_msg_data > 200) {
            printf("%lu%lu\n", MSG_SYSTEM_STATE, rx_msg_data);
        } else {
            printf("%lu%lu\n", MSG_WARNING, rx_msg_data);
        }
    }

    if (rx_msg_id == MSG_TEMP) {
        if (rx_msg_data < 250) {
            printf("%lu%lu\n", MSG_SYSTEM_STATE, rx_msg_data);
        } else {
            printf("%lu%lu\n", MSG_WARNING, rx_msg_data);
        }
    }

    if (rx_msg_id == MSG_SPEED_STATUS) {
        if (rx_msg_data == 0) {
            printf("%lu%lu\n", MSG_SYSTEM_STATE, rx_msg_data);
        } else {
            printf("%lu%lu\n", MSG_WARNING, rx_msg_data);
        }
    }
    return 0;
}