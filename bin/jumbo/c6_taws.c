// c6_taws.c - Terrain Awareness and Warning System
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    uint64_t altitude = 0;
    uint64_t vertical_speed = 0;
    uint64_t inputs_received = 0;
    
    // Read altitude message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    if (rx_msg_id == MSG_ALTITUDE) {
        altitude = rx_msg_data;
        inputs_received++;
    }
    
    // Read vertical speed message
    if (inputs_received == 1) {
        scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
        if (rx_msg_id == MSG_VERTICAL_SPEED) {
            vertical_speed = rx_msg_data;
            inputs_received++;
        }
    }
    
    // Generate terrain warnings based on altitude and descent rate
    if (inputs_received == 2) {
        uint64_t warning_level = 0;
        
        // Check for dangerous descent rate at low altitude
        if (altitude < 500 && vertical_speed > 2000) {
            warning_level = 3;  // "PULL UP! PULL UP!"
        } else if (altitude < 1000 && vertical_speed > 1500) {
            warning_level = 2;  // "TERRAIN! TERRAIN!"
        } else if (altitude < 2500 && vertical_speed > 1000) {
            warning_level = 1;  // "CAUTION TERRAIN"
        }
        
        if (warning_level > 0) {
            printf("%lu%lu\n", MSG_TERRAIN_WARNING, warning_level);
        }
    }
    
    return 0;
}