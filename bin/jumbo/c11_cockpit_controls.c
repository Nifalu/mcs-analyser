#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t pilot_input;

    scanf("%lu", &pilot_input);

    printf("%lu%lu\n", MSG_PILOT_INPUT, pilot_input);

    return 0;
}