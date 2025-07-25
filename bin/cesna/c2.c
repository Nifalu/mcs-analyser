// rpm_sensor.c
#include <stdio.h>
#include <stdint.h>
#include "can_messages.h"

int main() {
    uint64_t rpm_reading;

    // Read RPM from external sensor (arbitrary input)
    scanf("%lu", &rpm_reading);

    // Validate and send RPM data
    if (rpm_reading < 8000) {  // Max 8000 RPM
        printf("%lu%lu\n", MSG_ENGINE_RPM, rpm_reading);
    }

    return 0;
}