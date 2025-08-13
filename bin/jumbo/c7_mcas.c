#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);

    if (rx_msg_id == MSG_ANGLE_OF_ATTACK) {
        /* Due to faulty sensor, the message data is always 45 */

        if (rx_msg_data > 40) {
            printf("%lu%lu\n", MSG_TRIM_COMMAND, rx_msg_data);
        }

        if (rx_msg_data > 35) {
            printf("%lu%lu\n", MSG_STALL_WARNING, rx_msg_data);
        }
    }
    return 0;
}