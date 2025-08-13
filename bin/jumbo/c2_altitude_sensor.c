#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t altitude;

    scanf("%lu", &altitude);

    if (altitude < 40000) {
        printf("%lu%lu\n", MSG_ALTITUDE, altitude);
    }

    return 0;
}