#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    uint64_t engine;

    if (rx_msg_id == MSG_ENGINE_COMMAND) {
        // do some engine thingy
        engine = 1;
    }

    return 0;
}