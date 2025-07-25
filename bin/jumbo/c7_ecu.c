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
        
        switch (flight_mode) {
            case 1:  // GROUND - Idle thrust
                thrust_percent = 10;
                break;
            case 2:  // TAKEOFF - Maximum thrust
                thrust_percent = 100;
                break;
            case 3:  // CRUISE - Efficient thrust
                thrust_percent = 75;
                break;
            case 4:  // APPROACH - Reduced thrust
                thrust_percent = 40;
                break;
            case 5:  // CLIMB/DESCENT - Variable thrust
                thrust_percent = 85;
                break;
            default:
                thrust_percent = 50;
        }
        
        // Adjust for airspeed (simplified auto-throttle)
        if (airspeed < 150 && flight_mode > 1) {
            thrust_percent += 15;  // Need more thrust at low speed
        }
        
        // Send engine command
        printf("%lu%lu\n", MSG_ENGINE_COMMAND, thrust_percent);
        
        // Calculate expected engine parameters (for sensors to read)
        uint64_t expected_rpm = thrust_percent;
        uint64_t expected_temp = 300 + (thrust_percent * 6);  // 300-900 range
        
        printf("%lu%lu\n", MSG_ENGINE_RPM, expected_rpm);
        printf("%lu%lu\n", MSG_ENGINE_TEMP, expected_temp);
    }
    
    return 0;
}