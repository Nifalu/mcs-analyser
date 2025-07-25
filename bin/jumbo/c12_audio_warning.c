// c12_audio_warning.c - Audio Warning System (Consumer Only)
#include <stdio.h>
#include <stdint.h>
#include "aircraft_messages.h"

int main() {
    uint64_t rx_msg_id;
    uint64_t rx_msg_data;
    
    // Read warning message
    scanf("%lu%lu", &rx_msg_id, &rx_msg_data);
    
    // Local variables represent audio system state
    uint64_t audio_playing = 0;
    uint64_t audio_pattern = 0;  // Different patterns for different warnings
    uint64_t audio_volume = 0;
    
    // Process critical warnings only (level 3)
    if (rx_msg_data >= 3) {
        audio_playing = 1;
        audio_volume = 100;  // Maximum volume for critical warnings
        
        // Different audio patterns for different warning types
        if (rx_msg_id == MSG_TERRAIN_WARNING) {
            audio_pattern = 1;  // "PULL UP! PULL UP!" voice
        } else if (rx_msg_id == MSG_STALL_WARNING) {
            audio_pattern = 2;  // Stick shaker sound + "STALL! STALL!"
        } else if (rx_msg_id == MSG_ENGINE_WARNING) {
            audio_pattern = 3;  // Fire bell
        } else if (rx_msg_id == MSG_FUEL_WARNING) {
            audio_pattern = 4;  // "FUEL! FUEL!" voice
        }
    }
    // Process caution warnings (level 2)
    else if (rx_msg_data == 2) {
        audio_playing = 1;
        audio_volume = 75;
        
        if (rx_msg_id == MSG_TERRAIN_WARNING) {
            audio_pattern = 5;  // "TERRAIN! TERRAIN!" voice
        } else if (rx_msg_id == MSG_STALL_WARNING) {
            audio_pattern = 6;  // Continuous tone
        } else {
            audio_pattern = 7;  // General caution chime
        }
    }
    // No audio for advisory level (1) or no warning (0)
    else {
        audio_playing = 0;
        audio_volume = 0;
        audio_pattern = 0;
    }
    
    // In a real system, these variables would control the audio hardware
    // For analysis purposes, they remain as local state
    
    return 0;
}