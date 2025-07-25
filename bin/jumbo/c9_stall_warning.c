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
    
    // Generate stall warnings based on airspeed and flaps
    if (inputs_received == 2) {
        // Determine output priority
        if (airspeed < 80) {
            // Critical stall - highest priority
            printf("%lu%lu\n", MSG_STALL_WARNING, 2);
        } else if (airspeed < 120) {
            // Near stall - medium priority
            printf("%lu%lu\n", MSG_STALL_WARNING, (120 - airspeed) / 20);
        } else if (flaps_position > 20 && airspeed < 150) {
            // Configuration warning - send MFD update
            printf("%lu%lu\n", MSG_STALL_WARNING, ((150 - airspeed) << 8) | flaps_position);
        } else {
            // Normal flight - send basic MFD data
            printf("%lu%lu\n", MSG_STALL_WARNING, airspeed);
        }
    }
    
    return 0;
}