// c7_alarm.c - Alarm System (Consumer)
#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    
    // Read warning message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    
    if (rx_msg_id == MSG_WARNING) {
        // Local variables represent alarm state
        uint64_t alarm_on = 0;
        uint64_t alarm_pattern = 0;
        
        if (rx_msg_data == 2) {
            alarm_on = 1;
            alarm_pattern = 1;  // Fast beeping
        } else if (rx_msg_data == 1) {
            alarm_on = 1;
            alarm_pattern = 2;  // Slow beeping
        } else {
            alarm_on = 0;
            alarm_pattern = 0;  // Silent
        }
        
        // These would control actual alarm hardware
    }
    
    return 0;
}