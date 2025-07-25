// c4_fuel_system.c
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t fuel_pounds;
    
    // Read fuel quantity from sensors
    scanf("%lu", &fuel_pounds);
    
    // Send fuel level
    if (fuel_pounds <= 100000) {  // Max fuel capacity check
        printf("%lu%lu\n", MSG_FUEL_LEVEL, fuel_pounds);
        
        // Generate fuel warnings based on quantity
        if (fuel_pounds < 1000) {  // Critical fuel
            printf("%lu%lu\n", MSG_FUEL_WARNING, 3);  // Level 3 - Emergency
        } else if (fuel_pounds < 5000) {  // Low fuel
            printf("%lu%lu\n", MSG_FUEL_WARNING, 2);  // Level 2 - Caution
        } else if (fuel_pounds < 10000) {  // Fuel advisory
            printf("%lu%lu\n", MSG_FUEL_WARNING, 1);  // Level 1 - Advisory
        }
    }
    
    return 0;
}