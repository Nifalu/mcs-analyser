// c2_altitude_sensor.c
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t altitude_feet;
    uint64_t vertical_speed_fpm;  // Feet per minute
    
    // Read altitude and vertical speed (symbolic values)
    scanf("%lu", &altitude_feet);
    scanf("%lu", &vertical_speed_fpm);

    // Single output based on priority
    if (vertical_speed_fpm > 3000 && altitude_feet < 5000) {
        // Dangerous descent rate - priority
        printf("%lu%lu\n", MSG_VERTICAL_SPEED, vertical_speed_fpm);
    } else if (altitude_feet < 45000) {
        // Normal - send altitude
        printf("%lu%lu\n", MSG_ALTITUDE, altitude_feet);
    } else if (vertical_speed_fpm < 4000) {
        // High altitude, send vertical speed
        printf("%lu%lu\n", MSG_VERTICAL_SPEED, vertical_speed_fpm);
    }
    
    return 0;
}