// c5_quick_alert.c - Reads either sensor individually
#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id1;
    uint64_t rx_msg_data1;
    uint64_t rx_msg_id2;
    uint64_t rx_msg_data2;

    scanf("%lu%lu", &rx_msg_id1, &rx_msg_data1);
    if (rx_msg_id1 == MSG_SPEED) {
        scanf("%lu%lu", &rx_msg_id2, &rx_msg_data2);
        if (rx_msg_id2 == MSG_TEMP) {
            printf("%lu%lu\n", MSG_WARNING, 1);
        }
    } else if (rx_msg_id1 == MSG_TEMP) {
        printf("%lu%lu\n", MSG_WARNING, 1);
    }
    return 0;
}