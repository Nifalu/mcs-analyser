// messages.h
#ifndef MESSAGES_H
#define MESSAGES_H

#include <stdint.h>

// Sensor messages
const int64_t MSG_SPEED = 0x100;
const int64_t MSG_TEMP = 0x101;

// Component messages
const int64_t MSG_SPEED_STATUS = 0x200;
const int64_t MSG_SYSTEM_STATE = 0x201;
const int64_t MSG_WARNING = 0x202;

#endif