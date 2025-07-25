// c3_engine_monitor.c
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    uint64_t engine_temp = 0;
    uint64_t engine_rpm = 0;
    uint64_t inputs_received = 0;
    
    // Read first CAN message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    
    if (rx_msg_id == MSG_ENGINE_TEMP) {
        engine_temp = rx_msg_data;
        inputs_received++;
    } else if (rx_msg_id == MSG_ENGINE_RPM) {
        engine_rpm = rx_msg_data;
        inputs_received++;
    }
    
    // Read second CAN message if we got a valid first one
    if (inputs_received == 1) {
        scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
        
        if (rx_msg_id == MSG_ENGINE_TEMP) {
            engine_temp = rx_msg_data;
            inputs_received++;
        } else if (rx_msg_id == MSG_ENGINE_RPM) {
            engine_rpm = rx_msg_data;
            inputs_received++;
        }
    }
    
    // Generate output based on engine parameters
    if (inputs_received == 2) {

        // Determine output based on conditions
        if (engine_temp > 850 || (engine_rpm < 20 && engine_temp < 200)) {
            // Critical condition - send warning
            printf("%lu%lu\n", MSG_ENGINE_WARNING, 2);
        } else if (engine_temp > 700 || engine_rpm > 100) {
            // Caution condition - send warning
            printf("%lu%lu\n", MSG_ENGINE_WARNING, 1);
        } else {
            // Normal operation - send EICAS update
            printf("%lu%lu\n", MSG_EICAS_UPDATE, (engine_temp << 16) | engine_rpm);
        }
    }
    
    return 0;
}