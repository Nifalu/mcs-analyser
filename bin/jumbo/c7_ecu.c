// c7_ecu.c - Engine Control Unit
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    uint64_t flight_mode = 0;
    uint64_t airspeed = 0;
    uint64_t inputs_received = 0;
    
    // Read flight mode from FMC
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    if (rx_msg_id == MSG_FLIGHT_MODE) {
        flight_mode = rx_msg_data;
        inputs_received++;
    }
    
    // Read airspeed
    if (inputs_received == 1) {
        scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
        if (rx_msg_id == MSG_AIRSPEED) {
            airspeed = rx_msg_data;
            inputs_received++;
        }
    }
    
    // Calculate engine commands based on flight mode and airspeed
    if (inputs_received == 2) {
        uint64_t thrust_percent = 0;
        uint64_t output_type = 0;

        // Calculate thrust
        if (flight_mode == 1) {
            thrust_percent = 15;
        } else if (flight_mode == 3) {
            if (airspeed > 300) {
                thrust_percent = 70;
            } else if (airspeed < 200) {
                thrust_percent = 85;
            } else {
                thrust_percent = airspeed / 4;  // Symbolic calculation
            }
        } else {
            thrust_percent = 60 + (airspeed / 10);  // Symbolic
        }

        // Determine priority output
        if (thrust_percent > 90) {
            output_type = 1;  // High thrust - send temperature
        } else if (thrust_percent < 20 && flight_mode != 1) {
            output_type = 2;  // Low thrust in flight - send RPM
        } else {
            output_type = 0;  // Normal - send command
        }

        // Single printf based on priority
        if (output_type == 0) {
            printf("%lu%lu\n", MSG_ENGINE_COMMAND, thrust_percent);
        } else if (output_type == 1) {
            printf("%lu%lu\n", MSG_ENGINE_TEMP, 400 + (thrust_percent * 4));
        } else {
            printf("%lu%lu\n", MSG_ENGINE_RPM, thrust_percent);
        }
    }
    
    return 0;
}