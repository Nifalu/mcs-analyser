// c2_temp_sensor.c - Temperature Sensor (Producer)
#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t temperature;
    
    // Read temperature value (will be symbolic in analysis)
    scanf("%lu", &temperature);
    
    // Send temperature if within valid range
    if (temperature > 10 && temperature < 150) {
        printf("%lu%lu\n", MSG_TEMP, temperature);
    }
    
    return 0;
}