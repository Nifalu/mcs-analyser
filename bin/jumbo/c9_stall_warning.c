// c9_stall_warning.c - Stall Warning System
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    uint64_t airspeed = 0;
    uint64_t flaps_position = 0;
    uint64_t inputs_received = 0;
    
    // Read airspeed
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    if (rx_msg_id == MSG_AIRSPEED) {
        airspeed = rx_msg_data;
        inputs_received++;
    }
    
    // Read flaps position
    if (inputs_received == 1) {
        scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
        if (rx_msg_id == MSG_FLAPS_COMMAND) {
            flaps_position = rx_msg_data;
            inputs_received++;
        }
    }
    
    // Calculate stall speed based on flaps configuration
    if (inputs_received == 2) {
        uint64_t stall_speed = 140;  // Base stall speed in knots
        
        // Adjust stall speed for flaps
        if (flaps_position > 20) {
            stall_speed = 110;  // Lower stall speed with flaps
        } else if (flaps_position > 10) {
            stall_speed = 125;
        }
        
        // Check for stall conditions
        if (airspeed < stall_speed - 20) {
            // Stalled!
            printf("%lu%lu\n", MSG_STALL_WARNING, 3);  // Level 3 - STALL!
        } else if (airspeed < stall_speed - 10) {
            // Near stall
            printf("%lu%lu\n", MSG_STALL_WARNING, 2);  // Level 2 - Impending stall
        } else if (airspeed < stall_speed + 10) {
            // Approaching stall speed
            printf("%lu%lu\n", MSG_STALL_WARNING, 1);  // Level 1 - Caution
        }
        
        // Send data to MFD for angle of attack display
        uint64_t aoa_data = ((140 - airspeed) << 8) | flaps_position;
        printf("%lu%lu\n", MSG_MFD_UPDATE, aoa_data);
    }
    
    return 0;
}