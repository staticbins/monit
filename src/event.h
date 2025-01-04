/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU Affero General Public License in all respects
 * for all of the code used other than OpenSSL.
 */

#ifndef MONIT_EVENT_H
#define MONIT_EVENT_H

#include "monit.h"

// Original events (bits 0-31, unchanged)
#define Event_Null                         0x0ULL
#define Event_Checksum                     0x1ULL
#define Event_Timeout                      0x4ULL
#define Event_Size                        0x10ULL
#define Event_Connection                  0x20ULL
#define Event_Permission                  0x40ULL
#define Event_Uid                         0x80ULL
#define Event_Gid                        0x100ULL
#define Event_NonExist                   0x200ULL
#define Event_Invalid                    0x400ULL
#define Event_Data                       0x800ULL
#define Event_Exec                      0x1000ULL
#define Event_FsFlag                    0x2000ULL
#define Event_Icmp                      0x4000ULL
#define Event_Content                   0x8000ULL
#define Event_Instance                 0x10000ULL
#define Event_Action                   0x20000ULL
#define Event_Pid                      0x40000ULL
#define Event_PPid                     0x80000ULL
#define Event_Heartbeat               0x100000ULL
#define Event_Status                  0x200000ULL
#define Event_Uptime                  0x400000ULL
#define Event_Speed                  0x1000000ULL
#define Event_Saturation             0x2000000ULL
#define Event_ByteIn                 0x4000000ULL
#define Event_ByteOut                0x8000000ULL
#define Event_PacketIn              0x10000000ULL
#define Event_PacketOut             0x20000000ULL
#define Event_Exist                 0x40000000ULL

// Resource events (bits 32-47, giving 16 slots for resources)
#define Event_CPU                  0x100000000ULL  // bit 32
#define Event_TotalCPU             0x200000000ULL  // bit 33
#define Event_Memory               0x400000000ULL  // bit 34
#define Event_TotalMem             0x800000000ULL  // bit 35
#define Event_LoadAvg             0x1000000000ULL  // bit 36
#define Event_Space               0x2000000000ULL  // bit 37
#define Event_Inode               0x4000000000ULL  // bit 38
// Bits 39-47 reserved for future resource events
// 0x8000000000ULL through 0x800000000000ULL available

// Timestamp events (bits 48-51)
#define Event_AccessTime       0x1000000000000ULL  // bit 48
#define Event_ModifyTime       0x2000000000000ULL  // bit 49
#define Event_ChangeTime       0x4000000000000ULL  // bit 50
// Bit 51 reserved for future timestamp events

// Link events (bits 52-55)
#define Event_LinkStatus      0x10000000000000ULL // bit 52
#define Event_LinkErrors      0x20000000000000ULL // bit 53
// Bits 54-55 reserved for future link events

// Bits 56-63 available for future event categories

// All events mask (all 64 bits set)
#define Event_All           0xFFFFFFFFFFFFFFFFULL

// Grouped masks for convenience
#define Event_AllResource (Event_CPU | Event_TotalCPU | Event_Memory | Event_TotalMem | \
                          Event_LoadAvg | Event_Space | Event_Inode)
#define Event_AllTimestamp (Event_AccessTime | Event_ModifyTime | Event_ChangeTime)
#define Event_AllLink (Event_LinkStatus | Event_LinkErrors)


#define IS_EVENT_SET(value, mask) ((value & mask) != 0)

typedef struct EventTable_T {
        Event_Type id;
        const char *description_failed;
        const char *description_succeeded;
        const char *description_changed;
        const char *description_changednot;
        Check_State saveState; // Bitmap of the event states that should trigger state file update
} EventTable_T;


extern EventTable_T Event_Table[];


/**
 * This class implements the <b>event</b> processing machinery used by
 * monit. In monit an event is an object containing a Service_T
 * reference indicating the object where the event originated, an id
 * specifying the event type, a value representing up or down state
 * and an optional message describing why the event was fired.
 *
 * Clients may use the function Event_post() to post events to the
 * event handler for processing.
 *
 * @file
 */


/**
 * Post a new Event
 * @param service The Service the event belongs to
 * @param id The event identification
 * @param state The event state
 * @param action Description of the event action
 * @param s Optional message describing the event
 */
void Event_post(Service_T service, Event_Type id, Check_State state, EventAction_T action, const char *s, ...) __attribute__((format (printf, 5, 6)));


/**
 * Get a textual description of actual event type. For instance if the
 * event type is positive Event_Timestamp, the textual description is
 * "Timestamp error". Likewise if the event type is negative Event_Checksum
 * the textual description is "Checksum recovery" and so on.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_description(Event_T E);


/**
 * Get an event action id.
 * @param E An event object
 * @return An action id
 */
Action_Type Event_get_action(Event_T E);


/**
 * Get a textual description of actual event action. For instance if the
 * event type is positive Event_NonExist, the textual description of
 * failed state related action is "restart". Likewise if the event type is
 * negative Event_Checksum the textual description of recovery related action
 * is "alert" and so on.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_action_description(Event_T E);


/**
 * Reprocess the partially handled event queue
 */
void Event_queue_process(void);


#endif
