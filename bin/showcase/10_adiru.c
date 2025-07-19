#include <stdio.h>
#include <stdint.h>


int main() {
    uint64_t recipient1 = 11; // We want to talk to the Ground Proximity Warning System
    uint64_t recipient2 = 20; // We want to talk to the Autopilot
    uint64_t recipient3 = 101; // We want to talk to the Cockpit Displays
    uint64_t recipient4 = 102; // We want to talk to the Cabin Displays

    uint64_t cid = 10; // own ID

    uint64_t input;

     // Skip messages not targeted to us
    scanf("%lu", &input);
    if (input != cid) {
        return 0;
    }

    // do some calculations
    scanf("%lu", &input);
    uint64_t result = input % 100;

    // Send everything to cockpit, autopilot
    printf("%lu%lu\n", recipient2, input);
    printf("%lu%lu\n", recipient3, input);

    if (input < 30) {
        printf("%lu%lu\n", recipient1, input); // altitude to Ground Proximity Warning System
        printf("%lu%lu\n", recipient4, input); // altitude to cabin displays
    } else if (input > 300) {
        printf("%lu%lu\n", recipient4, input); // speed to cabin displays
    }

    return 0;
}