// c5_quick_alert.c - Reads either sensor individually
#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    
    // Read one message (could be either sensor)
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    
    uint64_t warning_level = 0;
    
    if (rx_msg_id == MSG_SPEED) {
        // Process speed
        if (rx_msg_data > 180) {
            warning_level = 2;  // High speed warning
        } else if (rx_msg_data < 30) {
            warning_level = 1;  // Low speed warning
        }
    } else if (rx_msg_id == MSG_TEMP) {
        // Process temperature
        if (rx_msg_data > 120) {
            warning_level = 2;  // High temp warning
        } else if (rx_msg_data < 20) {
            warning_level = 1;  // Low temp warning
        }
    }
    
    if (warning_level > 0) {
        printf("%lu%lu\n", MSG_WARNING, warning_level);
    }
    
    return 0;
}