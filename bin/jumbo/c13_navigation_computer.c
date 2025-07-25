// c13_navigation_computer.c - Navigation Computer
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    uint64_t altitude = 0;
    uint64_t airspeed = 0;
    uint64_t flight_mode = 0;
    uint64_t inputs_received = 0;

    // Read altitude
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    if (rx_msg_id == MSG_ALTITUDE) {
        altitude = rx_msg_data;
        inputs_received |= 1;
    }

    // Read airspeed
    if (inputs_received & 1) {
        scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
        if (rx_msg_id == MSG_AIRSPEED) {
            airspeed = rx_msg_data;
            inputs_received |= 2;
        }
    }

    // Read flight mode
    if (inputs_received == 3) {
        scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
        if (rx_msg_id == MSG_FLIGHT_MODE) {
            flight_mode = rx_msg_data;
            inputs_received |= 4;
        }
    }

    if (inputs_received == 7) {

        // Complex constraint propagation through conditions
        if (altitude > 20000 && airspeed > 250 && flight_mode == 3) {
            // Cruise conditions - send attitude
            printf("%lu%lu\n", MSG_ATTITUDE, 100);
        } else if (altitude < 5000 && airspeed < 200 && flight_mode == 2) {
            // Approach conditions - send MFD update
            printf("%lu%lu\n", MSG_MFD_UPDATE, (altitude / 100) + (airspeed / 10));
        } else if (altitude > 15000 && altitude < 25000 && airspeed > 300) {
            // Traffic alert conditions
            printf("%lu%lu\n", MSG_TRAFFIC_ALERT, 1);
        } else {
            // Normal navigation data
            printf("%lu%lu\n", MSG_ATTITUDE, airspeed / 5);
        }

    }
    
    return 0;
}