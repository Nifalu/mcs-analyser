// c1_airspeed_sensor.c
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t airspeed_knots;
    
    // Read airspeed (will be symbolic in analysis)
    scanf("%lu", &airspeed_knots);

    // Only send if within valid range (adds constraint)
    if (airspeed_knots > 50 && airspeed_knots < 400) {
        // Send actual airspeed value (symbolic)
        printf("%lu%lu\n", MSG_AIRSPEED, airspeed_knots);
    }
    
    return 0;
}