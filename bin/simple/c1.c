// temp_sensor.c
#include <stdio.h>
#include <stdint.h>
#include "can_messages.h"

int main() {
    uint64_t temp_reading;

    // Read temperature from external sensor (arbitrary input)
    scanf("%lu", &temp_reading);

    // Validate and send temperature data
    if (temp_reading < 300) {  // Max 300 degrees
        printf("%lu%lu\n", MSG_ENGINE_TEMP, temp_reading);
    }

    return 0;
}