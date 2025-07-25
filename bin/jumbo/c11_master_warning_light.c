// c11_master_warning_light.c - Master Warning Light (Consumer Only)
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    
    // Read PFD update message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    
    // Only process PFD updates
    if (rx_msg_id == MSG_PFD_UPDATE) {
        // Extract color from lower 24 bits
        uint64_t color = rx_msg_data & 0xFFFFFF;
        
        // Local variables represent physical hardware state
        uint64_t light_on = 0;
        uint64_t light_flashing = 0;
        uint64_t light_color = 0;
        
        // Red = Master Warning (flashing)
        if (color == 0xFF0000) {
            light_on = 1;
            light_flashing = 1;
            light_color = color;
        }
        // Amber = Master Caution (solid)
        else if (color == 0xFFAA00) {
            light_on = 1;
            light_flashing = 0;
            light_color = color;
        }
        // White = Advisory (no light)
        else {
            light_on = 0;
            light_flashing = 0;
            light_color = 0;
        }
        
        // In a real system, these would control actual hardware
        // For analysis, we just set local variables
    }
    
    return 0;
}