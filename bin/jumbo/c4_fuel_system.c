// c4_fuel_system.c
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t fuel_pounds;
    
    // Read fuel quantity from sensors
    scanf("%lu", &fuel_pounds);
    
    // Single output based on fuel level
    if (fuel_pounds < 2000) {
        // Critical fuel - send warning
        printf("%lu%lu\n", MSG_FUEL_WARNING, 2);
    } else if (fuel_pounds < 8000) {
        // Low fuel - send warning
        printf("%lu%lu\n", MSG_FUEL_WARNING, 1);
    } else if (fuel_pounds <= 100000) {
        // Normal - send fuel level
        printf("%lu%lu\n", MSG_FUEL_LEVEL, fuel_pounds);
    }
    
    return 0;
}