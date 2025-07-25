// c8_hydraulics.c - Hydraulic Control System
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    
    // Read hydraulic command
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    
    if (rx_msg_id == MSG_HYDRAULIC_COMMAND) {
        uint64_t command_value = rx_msg_data;
        
        // Simulate hydraulic system response
        uint64_t pressure_psi = 2000 + (command_value * 10);  // 2000-3000 PSI range
        
        // Send hydraulic pressure reading
        printf("%lu%lu\n", MSG_HYDRAULIC_PRESSURE, pressure_psi);
        
        // Based on command, determine landing gear and flaps position
        if (command_value < 40) {  // Low setting - gear down, flaps extended
            printf("%lu%lu\n", MSG_LANDING_GEAR_CMD, 1);  // 1 = DOWN
            printf("%lu%lu\n", MSG_FLAPS_COMMAND, 30);    // 30 degrees
        } else if (command_value > 60) {  // High setting - gear up, flaps retracted
            printf("%lu%lu\n", MSG_LANDING_GEAR_CMD, 0);  // 0 = UP
            printf("%lu%lu\n", MSG_FLAPS_COMMAND, 0);     // 0 degrees
        } else {  // Mid setting - gear up, partial flaps
            printf("%lu%lu\n", MSG_LANDING_GEAR_CMD, 0);  // 0 = UP
            printf("%lu%lu\n", MSG_FLAPS_COMMAND, 10);    // 10 degrees
        }
    }
    
    return 0;
}