#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    uint64_t hydraulic;

    if (rx_msg_id == MSG_HYDRAULIC_COMMAND) {
        // do some hydraulic thingy
        hydraulic = 1;
    } else if (rx_msg_id == MSG_TRIM_COMMAND) {
        hydraulic = 2;
    }

    return 0;
}