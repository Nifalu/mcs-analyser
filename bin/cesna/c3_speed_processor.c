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
        
        // Simple processing - two cases
        if (speed > 150) {
            status = 2;  // High speed
        } else if (speed > 50) {
            status = 1;  // Normal speed
        } else {
            status = 0;  // Low speed
        }
        
        printf("%lu%lu\n", MSG_SPEED_STATUS, status);
    }
    
    return 0;
}