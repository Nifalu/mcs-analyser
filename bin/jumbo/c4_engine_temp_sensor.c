#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t engine_temp;

    scanf("%lu", &engine_temp);

    if (engine_temp < 200) {
        printf("%lu%lu\n", MSG_ENGINE_TEMP, engine_temp);
    }

    return 0;
}