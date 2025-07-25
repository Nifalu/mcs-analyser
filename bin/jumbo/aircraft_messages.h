// aircraft_messages.h
#ifndef AIRCRAFT_MESSAGES_H
#define AIRCRAFT_MESSAGES_H

#include <stdint.h>

// Sensor Data Messages (0x100 - 0x1FF)
const int64_t MSG_AIRSPEED = 0x100;
const int64_t MSG_ALTITUDE = 0x101;
const int64_t MSG_VERTICAL_SPEED = 0x102;
const int64_t MSG_ENGINE_TEMP = 0x103;
const int64_t MSG_ENGINE_RPM = 0x104;
const int64_t MSG_FUEL_LEVEL = 0x105;
const int64_t MSG_HYDRAULIC_PRESSURE = 0x106;
const int64_t MSG_ATTITUDE = 0x107;  // Pitch/Roll/Yaw

// Control Messages (0x200 - 0x2FF)
const int64_t MSG_ENGINE_COMMAND = 0x200;
const int64_t MSG_FLIGHT_MODE = 0x201;
const int64_t MSG_HYDRAULIC_COMMAND = 0x202;
const int64_t MSG_LANDING_GEAR_CMD = 0x203;
const int64_t MSG_FLAPS_COMMAND = 0x204;

// Warning/Alert Messages (0x300 - 0x3FF)
const int64_t MSG_TERRAIN_WARNING = 0x300;
const int64_t MSG_TRAFFIC_ALERT = 0x301;
const int64_t MSG_WEATHER_ALERT = 0x302;
const int64_t MSG_ENGINE_WARNING = 0x303;
const int64_t MSG_FUEL_WARNING = 0x304;
const int64_t MSG_STALL_WARNING = 0x305;

// Display Messages (0x400 - 0x4FF)
const int64_t MSG_PFD_UPDATE = 0x400;  // Primary Flight Display
const int64_t MSG_MFD_UPDATE = 0x401;  // Multi-Function Display
const int64_t MSG_EICAS_UPDATE = 0x402;  // Engine Indication and Crew Alerting System

#endif