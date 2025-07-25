// c1_airspeed_sensor.c
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t airspeed_knots;
    
    // Read airspeed from pitot tube sensor (external input)
    scanf("%lu", &airspeed_knots);
    
    // Validate airspeed range (0-600 knots typical for commercial aircraft)
    if (airspeed_knots <= 600) {
        // Send airspeed data on CAN bus
        printf("%lu%lu\n", MSG_AIRSPEED, airspeed_knots);
    }
    
    return 0;
}