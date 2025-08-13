#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t speed;

    scanf("%lu", &speed);

    /* surely the sensor is faulty if
       the speed is higher than that.
       nobody is going to fly that fast anyway.
     */
    if (speed < 2000) {
        printf("%lu%lu\n", MSG_AIRSPEED, speed);
    }

    return 0;
}