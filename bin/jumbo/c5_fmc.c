// c5_fmc.c - Flight Management Computer
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    uint64_t altitude = 0;
    uint64_t airspeed = 0;
    uint64_t fuel_level = 0;
    uint64_t inputs_received = 0;
    
    // FMC needs to read 3 different message types
    for (int i = 0; i < 3; i++) {
        scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
        
        if (rx_msg_id == MSG_ALTITUDE) {
            altitude = rx_msg_data;
            inputs_received |= 1;
        } else if (rx_msg_id == MSG_AIRSPEED) {
            airspeed = rx_msg_data;
            inputs_received |= 2;
        } else if (rx_msg_id == MSG_FUEL_LEVEL) {
            fuel_level = rx_msg_data;
            inputs_received |= 4;
        }
    }
    
    // Only proceed if we got all required inputs
    if (inputs_received == 7) {  // All 3 bits set
        uint64_t flight_mode = 0;
        uint64_t output_state = 0;  // Determines which output to send

        // Determine flight mode
        if (altitude < 100) {
            flight_mode = 1;  // GROUND
        } else if (altitude > 10000) {
            flight_mode = 3;  // CRUISE
        } else {
            flight_mode = 2;  // CLIMB/DESCENT
        }

        // Determine which output to send based on conditions
        if (altitude < 1000 && airspeed < 150) {
            output_state = 1;  // Send hydraulic command
        } else if (altitude > 5000 && fuel_level < 10000) {
            output_state = 2;  // Send PFD update
        } else {
            output_state = 0;  // Send flight mode
        }

        // Single printf based on state
        if (output_state == 0) {
            printf("%lu%lu\n", MSG_FLIGHT_MODE, flight_mode);
        } else if (output_state == 1) {
            printf("%lu%lu\n", MSG_HYDRAULIC_COMMAND, flight_mode * 20);
        } else {
            uint64_t pfd_data = (altitude << 16) | (airspeed & 0xFFFF);
            printf("%lu%lu\n", MSG_PFD_UPDATE, pfd_data);
        }
    }
    
    return 0;
}