#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t engine_rpm;

    scanf("%lu", &engine_rpm);

    if (engine_rpm < 10000) {
        printf("%lu%lu\n", MSG_ENGINE_RPM, engine_rpm);
    }

    return 0;
}