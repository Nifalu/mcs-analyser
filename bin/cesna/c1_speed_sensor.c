// c1_speed_sensor.c - Speed Sensor (Producer)
#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t speed;
    
    // Read speed value (will be symbolic in analysis)
    scanf("%lu", &speed);
    
    // Send speed if within valid range
    if (speed < 2000) {
        printf("%lu%lu\n", MSG_SPEED, speed);
    }
    
    return 0;
}