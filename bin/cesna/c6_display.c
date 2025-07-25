// c6_display.c - Display Unit (Consumer)
#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    
    // Read system state message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    
    if (rx_msg_id == MSG_SYSTEM_STATE) {
        // Local variables represent display state
        uint64_t display_color = 0;
        uint64_t display_text = 0;
        
        if (rx_msg_data == 3) {
            display_color = 0xFF0000;  // Red
            display_text = 1;  // "CRITICAL"
        } else if (rx_msg_data == 2) {
            display_color = 0xFFAA00;  // Amber
            display_text = 2;  // "WARNING"
        } else {
            display_color = 0x00FF00;  // Green
            display_text = 3;  // "NORMAL"
        }
        
        // These would control actual display hardware
    }
    
    return 0;
}