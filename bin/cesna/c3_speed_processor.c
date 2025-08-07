// c3_speed_processor.c - Reads only speed, produces status
#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    
    // Read speed message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    
    if (rx_msg_id == MSG_SPEED) {
        uint64_t speed = rx_msg_data;
        uint64_t status;

        if (speed > 2000) {
            printf("%lu%lu\n", MSG_WARNING, 2);
        } else if (speed > 1000) {
            printf("%lu%lu\n", MSG_SPEED_STATUS, 1);
        } else if (speed > 50) {
            printf("%lu%lu\n", MSG_SPEED_STATUS, 0);
        }
        

    }
    
    return 0;
}