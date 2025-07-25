// can_messages.h
#ifndef CAN_MESSAGES_H
#define CAN_MESSAGES_H

// Simple const variables - names will be in the symbol table
const int64_t MSG_ENGINE_TEMP = 0x100;
const int64_t MSG_ENGINE_RPM = 0x101;
const int64_t MSG_ENGINE_HEALTH = 0x102;
const int64_t MSG_FUEL_LEVEL = 0x103;
const int64_t MSG_OIL_PRESSURE = 0x104;
const int64_t MSG_BRAKE_COMMAND = 0x200;
const int64_t MSG_BRAKE_STATUS = 0x201;
const int64_t MSG_WARNING_LIGHT = 0x301;

#endif