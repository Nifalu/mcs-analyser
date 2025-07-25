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

        // Determine output based on command
        if (command_value < 40) {
            printf("%lu%lu\n", MSG_LANDING_GEAR_CMD, 1);
        } else if (command_value > 60) {
            printf("%lu%lu\n", MSG_FLAPS_COMMAND, 0);
        } else {
            printf("%lu%lu\n", MSG_HYDRAULIC_PRESSURE, 2000 + command_value * 10);
        }


    }
    
    return 0;
}