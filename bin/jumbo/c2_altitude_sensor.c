// c2_altitude_sensor.c
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t altitude_feet;
    uint64_t vertical_speed_fpm;  // Feet per minute
    
    // Read altitude from barometric sensor
    scanf("%lu", &altitude_feet);
    
    // Read vertical speed
    scanf("%lu", &vertical_speed_fpm);
    
    // Validate altitude (max 50,000 feet)
    if (altitude_feet <= 50000) {
        printf("%lu%lu\n", MSG_ALTITUDE, altitude_feet);
    }
    
    // Validate vertical speed (±6000 fpm typical max)
    if (vertical_speed_fpm <= 6000) {
        printf("%lu%lu\n", MSG_VERTICAL_SPEED, vertical_speed_fpm);
    }
    
    return 0;
}