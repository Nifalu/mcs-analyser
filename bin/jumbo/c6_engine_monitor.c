#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;

    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);

    if (rx_msg_id == MSG_ENGINE_RPM) {
        if (rx_msg_data > 8000) {
            printf("%lu%lu\n", MSG_ENGINE_WARNING, rx_msg_data);
        }
    } else if (rx_msg_id == MSG_ENGINE_TEMP) {
        if (rx_msg_data > 100) {
            printf("%lu%lu\n", MSG_ENGINE_WARNING, rx_msg_data);
        }
    }

    return 0;
}