// c10_pfd.c - Primary Flight Display (simplified)
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    uint64_t warning_level = 0;

    // Read a single warning message and display it
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);

    // Check which type of warning we received
    if (rx_msg_id == MSG_TERRAIN_WARNING ||
        rx_msg_id == MSG_STALL_WARNING ||
        rx_msg_id == MSG_ENGINE_WARNING ||
        rx_msg_id == MSG_FUEL_WARNING) {

        warning_level = rx_msg_data;

        // Determine display color based on warning level
        uint64_t display_color;
        if (warning_level >= 2) {
            // Master Warning - Red
            display_color = 0xFF0000;
        } else if (warning_level >= 1) {
            // Master Caution - Amber
            display_color = 0xFFAA00;
        } else {
            // Advisory - White
            display_color = 0xFFFFFF;
        }

        // Send PFD update with color and warning info
        printf("%lu%lu\n", MSG_PFD_UPDATE, display_color | (rx_msg_id << 24));
    }
    
    return 0;
}