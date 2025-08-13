#include <stdio.h>
#include <stdint.h>
#include "messages.h"

int main() {
    uint64_t angle;

    scanf("%lu", &angle);

    /* broken sensor always reports 45 degrees*/
    printf("%lu%lu\n", MSG_ANGLE_OF_ATTACK, 45);
    return 0;
}