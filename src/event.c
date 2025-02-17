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

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif


#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#include "monit.h"
#include "alert.h"
#include "event.h"
#include "state.h"
#include "MMonit.h"
#include "spawn.h"

// libmonit
#include "io/File.h"
#include "system/Time.h"

/**
 * Implementation of the event interface.
 *
 * @file
 */


/* ------------------------------------------------------------- Definitions */

EventTable_T Event_Table[] = {
        {Event_Action,     "Action done",               "Action done",                "Action done",              "Action done",                  State_None},
        {Event_ByteIn,     "Download bytes exceeded",   "Download bytes ok",          "Download bytes changed",   "Download bytes not changed",   State_None},
        {Event_ByteOut,    "Upload bytes exceeded",     "Upload bytes ok",            "Upload bytes changed",     "Upload bytes not changed",     State_None},
        {Event_Checksum,   "Checksum failed",           "Checksum succeeded",         "Checksum changed",         "Checksum not changed",         State_None},
        {Event_Connection, "Connection failed",         "Connection succeeded",       "Connection changed",       "Connection not changed",       State_Changed},
        {Event_Content,    "Content failed",            "Content succeeded",          "Content match",            "Content doesn't match",        State_Changed},
        {Event_Data,       "Data access error",         "Data access succeeded",      "Data access changed",      "Data access not changed",      State_None},
        {Event_Exec,       "Execution failed",          "Execution succeeded",        "Execution changed",        "Execution not changed",        State_None},
        {Event_FsFlag,     "Filesystem flags failed",   "Filesystem flags succeeded", "Filesystem flags changed", "Filesystem flags not changed", State_None},
        {Event_Gid,        "GID failed",                "GID succeeded",              "GID changed",              "GID not changed",              State_None},
        {Event_Heartbeat,  "Heartbeat failed",          "Heartbeat succeeded",        "Heartbeat changed",        "Heartbeat not changed",        State_None},
        {Event_Icmp,       "ICMP failed",               "ICMP succeeded",             "ICMP changed",             "ICMP not changed",             State_None},
        {Event_Instance,   "Monit instance failed",     "Monit instance succeeded",   "Monit instance changed",   "Monit instance not changed",   State_None},
        {Event_Invalid,    "Invalid type",              "Type succeeded",             "Type changed",             "Type not changed",             State_None},
        {Event_Link,       "Link down",                 "Link up",                    "Link changed",             "Link not changed",             State_None},
        {Event_NonExist,   "Does not exist",            "Exists",                     "Existence changed",        "Existence not changed",        State_None},
        {Event_PacketIn,   "Download packets exceeded", "Download packets ok",        "Download packets changed", "Download packets not changed", State_None},
        {Event_PacketOut,  "Upload packets exceeded",   "Upload packets ok",          "Upload packets changed",   "Upload packets not changed",   State_None},
        {Event_Permission, "Permission failed",         "Permission succeeded",       "Permission changed",       "Permission not changed",       State_None},
        {Event_Pid,        "PID failed",                "PID succeeded",              "PID changed",              "PID not changed",              State_None},
        {Event_PPid,       "PPID failed",               "PPID succeeded",             "PPID changed",             "PPID not changed",             State_None},
        {Event_Resource,   "Resource limit matched",    "Resource limit succeeded",   "Resource limit changed",   "Resource limit not changed",   State_None},
        {Event_Saturation, "Saturation exceeded",       "Saturation ok",              "Saturation changed",       "Saturation not changed",       State_None},
        {Event_Size,       "Size failed",               "Size succeeded",             "Size changed",             "Size not changed",             State_Changed},
        {Event_Speed,      "Speed failed",              "Speed ok",                   "Speed changed",            "Speed not changed",            State_Changed},
        {Event_Status,     "Status failed",             "Status succeeded",           "Status changed",           "Status not changed",           State_None},
        {Event_Timeout,    "Timeout",                   "Timeout recovery",           "Timeout changed",          "Timeout not changed",          State_None},
        {Event_Timestamp,  "Timestamp failed",          "Timestamp succeeded",        "Timestamp changed",        "Timestamp not changed",        State_Changed},
        {Event_Uid,        "UID failed",                "UID succeeded",              "UID changed",              "UID not changed",              State_None},
        {Event_Uptime,     "Uptime failed",             "Uptime succeeded",           "Uptime changed",           "Uptime not changed",           State_None},
        {Event_Exist,      "Does exist",                "Exists not",                 "Existence changed",        "Existence not changed",        State_None},
        /* Virtual events */
        {Event_Null,       "No Event",                  "No Event",                   "No Event",                 "No Event",                     State_None}
};


/* ----------------------------------------------------------------- Private */


static void _saveState(long id, State_Type state) {
        EventTable_T *et = Event_Table;
        while ((*et).id) {
                if ((*et).id == id) {
                        if ((*et).saveState & state) {
                                State_dirty();
                        }
                        break;
                }
                et++;
        }
}


/**
 * Return the actual event state based on event state bitmap and event ratio needed to trigger the state change
 * @param E An event object
 * @param S Actual posted state
 * @return The event state
 */
static bool _checkState(Event_T E, State_Type S) {
        assert(E);
        int count = 0;
        State_Type state = (S == State_Succeeded || S == State_ChangedNot) ? State_Succeeded : State_Failed; /* translate to 0/1 class */

        /* Only failed/changed state condition can change the initial state */
        if (! state && E->state == State_Init && ! (E->source->error & E->id))
                return false;

        Action_T action = ! state ? E->action->succeeded : E->action->failed;

        /* Compare as many bits as cycles able to trigger the action */
        for (int i = 0; i < action->cycles; i++) {
                /* Check the state of the particular cycle given by the bit position */
                State_Type flag = (E->state_map >> i) & 0x1;

                /* Count occurrences of the posted state */
                if (flag == state)
                        count++;
        }

        /* the internal instance and action events are handled as changed any time since we need to deliver alert whenever it occurs */
        if (E->id == Event_Instance || E->id == Event_Action || (count >= action->count && (S != E->state || S == State_Changed))) {
                memset(&(E->state_map), state, sizeof(E->state_map)); // Restart state map on state change, so we'll not flicker on multiple-failures condition (next state change requires full number of cycles to pass)
                return true;
        }

        return false;
}


/**
 * Add the partially handled event to the global queue
 * @param E An event object
 */
static void _queueAdd(Event_T E) {
        assert(E);
        assert(E->flag != Handler_Succeeded);

        if (! file_checkQueueDirectory(Run.eventlist_dir)) {
                Log_error("Aborting event - cannot access the event queue directory %s\n", Run.eventlist_dir);
                return;
        }

        if (! file_checkQueueLimit(Run.eventlist_dir, Run.eventlist_slots)) {
                Log_error("Aborting event - queue over quota\n");
                return;
        }

        /* compose the file name of actual timestamp and service name */
        char file_name[PATH_MAX];
        snprintf(file_name, PATH_MAX, "%s/%lld_%lx", Run.eventlist_dir, (long long)Time_now(), (long unsigned)E->source->name);

        Log_info("Adding event to the queue file %s for later delivery\n", file_name);

        FILE *file = fopen(file_name, "w");
        if (! file) {
                Log_error("Aborting event - cannot create event file %s -- %s\n", file_name, STRERROR);
                return;
        }

        bool rv;

        /* write event structure version */
        int version = EVENT_VERSION;
        if (! (rv = file_writeQueue(file, &version, sizeof(int))))
                goto error;

        /* write event structure */
        if (! (rv = file_writeQueue(file, E, sizeof(*E))))
                goto error;

        /* write source */
        if (! (rv = file_writeQueue(file, E->source->name, strlen(E->source->name) + 1)))
                goto error;

        /* write message */
        if (! (rv = file_writeQueue(file, E->message, E->message ? strlen(E->message) + 1 : 0)))
                goto error;

        /* write event action */
        Action_Type action = Event_get_action(E);
        if (! (rv = file_writeQueue(file, &action, sizeof(Action_Type))))
                goto error;

error:
        fclose(file);
        if (! rv) {
                Log_error("Aborting event - unable to save event information to %s\n",  file_name);
                if (unlink(file_name) < 0)
                        Log_error("Failed to remove event file '%s' -- %s\n", file_name, STRERROR);
        } else {
                if (! (Run.flags & Run_HandlerInit) && E->flag & Handler_Alert)
                        Run.handler_queue[Handler_Alert]++;
                if (! (Run.flags & Run_HandlerInit) && E->flag & Handler_Mmonit)
                        Run.handler_queue[Handler_Mmonit]++;
        }
}


/**
 * Update the partially handled event in the global queue
 * @param E An event object
 * @param file_name File name
 */
static void _queueUpdate(Event_T E, const char *file_name) {
        int version = EVENT_VERSION;
        Action_Type action = Event_get_action(E);
        bool rv;

        assert(E);
        assert(E->flag != Handler_Succeeded);

        if (! file_checkQueueDirectory(Run.eventlist_dir)) {
                Log_error("Aborting event - cannot access the event queue directory %s\n", Run.eventlist_dir);
                return;
        }

        DEBUG("Updating event in the queue file %s for later delivery\n", file_name);

        FILE *file = fopen(file_name, "w");
        if (! file) {
                Log_error("Aborting event - cannot open the event file %s -- %s\n", file_name, STRERROR);
                return;
        }

        /* write event structure version */
        if (! (rv = file_writeQueue(file, &version, sizeof(int))))
                goto error;

        /* write event structure */
        if (! (rv = file_writeQueue(file, E, sizeof(*E))))
                goto error;

        /* write source */
        if (! (rv = file_writeQueue(file, E->source->name, strlen(E->source->name) + 1)))
                goto error;

        /* write message */
        if (! (rv = file_writeQueue(file, E->message, E->message ? strlen(E->message) + 1 : 0)))
                goto error;

        /* write event action */
        if (! (rv = file_writeQueue(file, &action, sizeof(Action_Type))))
                goto error;

error:
        fclose(file);
        if (! rv) {
                Log_error("Aborting event - unable to update event information in '%s'\n", file_name);
                if (unlink(file_name) < 0)
                        Log_error("Failed to remove event file '%s' -- %s\n", file_name, STRERROR);
        }
}


static void _handleAction(Event_T E, Action_T A) {
        assert(E);
        assert(A);

        E->flag = Handler_Succeeded;

        if (A->id != Action_Ignored) {
                if (A->id == Action_Exec) {
                        if (E->state_changed || (E->state && A->repeat && E->count % A->repeat == 0)) {
                                Log_info("'%s' exec: '%s'\n", E->source->name, Util_commandDescription(A->exec, (char[STRLEN]){}));
                                char spawn_error[STRLEN] = {"?"};
                                if (spawn(&(struct spawn_args_t){
                                        .S = E->source,
                                        .cmd = A->exec,
                                        .E = E,
                                        .err = spawn_error,
                                        .errlen = STRLEN
                                }) < 0) {
                                        Log_error("'%s' exec failed -- '%s'\n", E->source->name, spawn_error);
                                        return;
                                }
                        }
                } else if (A->id != Action_Alert && E->id != Event_Instance) {
                        // For Instance events we don't want actions like stop to be executed to prevent the disabling of system service monitoring
                        if (E->source->actionratelist && (A->id == Action_Start || A->id == Action_Restart)) {
                                E->source->nstart++;
                                State_dirty();
                        }
                        if (E->source->mode != Monitor_Passive || (A->id != Action_Start && A->id != Action_Stop && A->id != Action_Restart))
                                control_service(E->source->name, A->id);
                }

                // Alert and mmonit event notification are common actions
                E->flag |= MMonit_send(E);
                E->flag |= handle_alert(E);

                // Retry the event for failed handlers
                if (E->flag != Handler_Succeeded) {
                        if (Run.eventlist_dir)
                                _queueAdd(E);
                        else
                                Log_error("Aborting event\n");
                }
        }
}


static void _handleEvent(Service_T S, Event_T E) {
        assert(E);
        assert(E->action);
        assert(E->action->failed);
        assert(E->action->succeeded);

        /* We will handle only first succeeded event, recurrent succeeded events
         * or insufficient succeeded events during failed service state are
         * ignored. Failed events are handled each time. */
        if (! E->state_changed && (E->state == State_Succeeded || E->state == State_ChangedNot || ((E->state_map & 0x1) ^ 0x1))) {
                DEBUG("'%s' %s\n", S->name, E->message);
                return;
        }

        if (E->message) {
                if (E->id == Event_Instance || E->id == Event_Action) {
                        // Instance and action events are logged always with priority info
                        Log_info("'%s' %s\n", S->name, E->message);
                } else if (E->state == State_Succeeded || E->state == State_ChangedNot) {
                        if (E->state_map & 0x1) {
                                // Failure, but didn't reach the error threshold yet
                                Log_warning("'%s' %s\n", S->name, E->message);
                        } else {
                                // Success
                                Log_info("'%s' %s\n", S->name, E->message);
                        }
                } else if (E->state == State_Init) {
                        if (E->state_map & 0x1) {
                                // Log error which occur while the service is initializing as warnings, success is not logged in the initializing state
                                Log_warning("'%s' %s\n", S->name, E->message);
                        }
                        return;
                } else {
                        Log_error("'%s' %s\n", S->name, E->message);
                }
        }

        if (E->state == State_Failed || E->state == State_Changed) {
                if (E->id != Event_Instance && E->id != Event_Action) { // We are not interested in setting error flag for instance and action events
                        S->error |= E->id;
                        /* The error hint provides second dimension for error bitmap and differentiates between failed/changed event states (failed=0, changed=1) */
                        if (E->state == State_Changed)
                                S->error_hint |= E->id;
                        else
                                S->error_hint &= ~E->id;
                }
                _handleAction(E, E->action->failed);
        } else {
                S->error &= ~E->id;
                _handleAction(E, E->action->succeeded);
        }
}


#if defined(__clang__) && defined(__clang_major__) && __clang_major__ >= 12
__attribute__((no_sanitize("unsigned-integer-overflow", "unsigned-shift-base")))
#elif defined(__clang__) && defined(__clang_major__) && __clang_major__ >= 4
__attribute__((no_sanitize("unsigned-integer-overflow")))
#endif
static unsigned long long left_shift(unsigned long long v) {
        return v << 1;
}


/* ------------------------------------------------------------------ Public */


/**
 * Post a new Event
 * @param service The Service the event belongs to
 * @param id The event identification
 * @param state The event state
 * @param action Description of the event action
 * @param s Optional message describing the event
 */
void Event_post(Service_T service, long id, State_Type state, EventAction_T action, const char *s, ...) {
        assert(service);
        assert(action);
        assert(s);
        assert(state == State_Failed || state == State_Succeeded || state == State_Changed || state == State_ChangedNot);

        _saveState(id, state);

        va_list ap;
        va_start(ap, s);
        char *message = Str_vcat(s, ap);
        va_end(ap);

        Event_T e = service->eventlist;
        while (e) {
                if (e->action == action && e->id == id) {
                        gettimeofday(&e->collected, NULL);

                        /* Shift the existing event flags to the left and set the first bit based on actual state */
                        e->state_map = left_shift(e->state_map);
                        e->state_map |= ((state == State_Succeeded || state == State_ChangedNot) ? 0 : 1);

                        /* Update the message */
                        FREE(e->message);
                        e->message = message;
                        break;
                }
                e = e->next;
        }
        if (! e) {
                /* Only first failed/changed event can initialize the queue for given event type, thus succeeded events are ignored until first error. */
                if (state == State_Succeeded || state == State_ChangedNot) {
                        DEBUG("'%s' %s\n", service->name, message);
                        FREE(message);
                        return;
                }
                /* Initialize the event. The mandatory information is cloned so the event is as standalone as possible and may be saved
                 * to the queue without the dependency on the original service, thus persistent and manageable across monit restarts */
                NEW(e);
                e->id = id;
                gettimeofday(&e->collected, NULL);
                e->source = service;
                e->mode = service->mode;
                e->type = service->type;
                e->state = State_Init;
                e->state_map = 1;
                e->action = action;
                e->message = message;
                e->next = service->eventlist;
                service->eventlist = e;
        }
        e->state_changed = _checkState(e, state);
        /* In the case that the state changed, update it and reset the counter */
        if (e->state_changed) {
                e->state = state;
                e->count = 1;
        } else {
                e->count++;
        }
        _handleEvent(service, e);
}


/**
 * Get a textual description of actual event type.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_description(Event_T E) {
        assert(E);
        EventTable_T *et = Event_Table;
        while ((*et).id) {
                if (E->id == (*et).id) {
                        switch (E->state) {
                                case State_Succeeded:
                                        return (*et).description_succeeded;
                                case State_Failed:
                                        return (*et).description_failed;
                                case State_Init:
                                        return (*et).description_failed;
                                case State_Changed:
                                        return (*et).description_changed;
                                case State_ChangedNot:
                                        return (*et).description_changednot;
                                default:
                                        break;
                        }
                }
                et++;
        }
        return NULL;
}


/**
 * Get an event action id.
 * @param E An event object
 * @return An action id
 */
Action_Type Event_get_action(Event_T E) {
        assert(E);
        Action_T A = NULL;
        switch (E->state) {
                case State_Succeeded:
                case State_ChangedNot:
                        A = E->action->succeeded;
                        break;
                case State_Failed:
                case State_Changed:
                case State_Init:
                        A = E->action->failed;
                        break;
                default:
                        Log_error("Invalid event state: %d\n", E->state);
                        return Action_Ignored;
        }
        if (! A)
                return Action_Ignored;
        /* In the case of passive mode we replace the description of start, stop or restart action for alert action, because these actions are passive in this mode */
        return (E->mode == Monitor_Passive && ((A->id == Action_Start) || (A->id == Action_Stop) || (A->id == Action_Restart))) ? Action_Alert : A->id;
}


/**
 * Get a textual description of actual event action. For instance if the
 * event type is positive Event_NonExist, the textual description of
 * failed state related action is "restart". Likewise if the event type is
 * negative Event_Checksumthe textual description of recovery related action
 * is "alert" and so on.
 * @param E An event object
 * @return A string describing the event type in clear text. If the
 * event type is not found NULL is returned.
 */
const char *Event_get_action_description(Event_T E) {
        assert(E);
        return Action_Names[Event_get_action(E)];
}


/**
 * Reprocess the partially handled event queue
 */
void Event_queue_process(void) {
        /* return in the case that the eventqueue is not enabled or empty */
        if (! Run.eventlist_dir || (! (Run.flags & Run_HandlerInit) && ! Run.handler_queue[Handler_Alert] && ! Run.handler_queue[Handler_Mmonit]))
                return;

        DIR *dir = opendir(Run.eventlist_dir);
        if (! dir) {
                if (errno != ENOENT)
                        Log_error("Cannot open the directory %s -- %s\n", Run.eventlist_dir, STRERROR);
                return;
        }

        struct dirent *de = readdir(dir);
        if (de)
                DEBUG("Processing postponed events queue\n");

        Action_T a;
        NEW(a);

        EventAction_T ea;
        NEW(ea);

        while (de) {
                int handlers_passed = 0;

                /* In the case that all handlers failed, skip the further processing in this cycle. Alert handler is currently defined anytime (either explicitly or localhost by default) */
                if ( (Run.mmonits && FLAG(Run.handler_flag, Handler_Mmonit) && FLAG(Run.handler_flag, Handler_Alert)) || FLAG(Run.handler_flag, Handler_Alert))
                        break;

                char file_name[PATH_MAX];
                snprintf(file_name, sizeof(file_name), "%s/%s", Run.eventlist_dir, de->d_name);

                if (File_isFile(file_name)) {
                        DEBUG("Processing queued event '%s'\n", file_name);

                        FILE *file = fopen(file_name, "r");
                        if (! file) {
                                Log_error("Queued event processing failed - cannot open the file '%s' -- %s\n", file_name, STRERROR);
                                goto error1;
                        }

                        size_t size;

                        /* read event structure version */
                        int *version = file_readQueue(file, &size);
                        if (! version) {
                                DEBUG("Skipping file '%s' - not event queue data formatted\n", file_name);
                                goto error2;
                        }
                        if (size != sizeof(int)) {
                                Log_error("Aborting queued event %s - invalid size %lu\n", file_name, (unsigned long)size);
                                goto error3;
                        }
                        if (*version != EVENT_VERSION) {
                                Log_error("Aborting queued event %s - incompatible data format version %d\n", file_name, *version);
                                goto error3;
                        }

                        /* read event structure */
                        Event_T e = file_readQueue(file, &size);
                        if (! e)
                                goto error3;
                        if (size != sizeof(*e))
                                goto error4;

                        /* read source */
                        char *service = file_readQueue(file, &size);
                        if (! service)
                                goto error4;
                        if (! (e->source = Util_getService(service))) {
                                Log_error("Aborting queued event '%s' - service %s not found in monit configuration\n", file_name, service);
                                FREE(service);
                                goto error4;
                        }
                        FREE(service);

                        /* read message */
                        if (! (e->message = file_readQueue(file, &size)))
                                goto error4;

                        /* read event action */
                        Action_Type *action = file_readQueue(file, &size);
                        if (! action)
                                goto error5;
                        if (size != sizeof(Action_Type))
                                goto error6;
                        a->id = *action;
                        switch (e->state) {
                                case State_Succeeded:
                                case State_ChangedNot:
                                        ea->succeeded = a;
                                        break;
                                case State_Failed:
                                case State_Changed:
                                case State_Init:
                                        ea->failed = a;
                                        break;
                                default:
                                        Log_error("Aborting queue event %s -- invalid state: %d\n", file_name, e->state);
                                        goto error6;
                        }
                        e->action = ea;

                        /* Retry all remaining handlers */

                        /* alert */
                        if (e->flag & Handler_Alert) {
                                if (Run.flags & Run_HandlerInit)
                                        Run.handler_queue[Handler_Alert]++;
                                if ((Run.handler_flag & Handler_Alert) != Handler_Alert) {
                                        if (handle_alert(e) != Handler_Alert) {
                                                e->flag &= ~Handler_Alert;
                                                Run.handler_queue[Handler_Alert]--;
                                                handlers_passed++;
                                        } else {
                                                Log_error("Alert handler failed, retry scheduled for next cycle\n");
                                                Run.handler_flag |= Handler_Alert;
                                        }
                                }
                        }

                        /* mmonit */
                        if (e->flag & Handler_Mmonit) {
                                if (Run.flags & Run_HandlerInit)
                                        Run.handler_queue[Handler_Mmonit]++;
                                if ((Run.handler_flag & Handler_Mmonit) != Handler_Mmonit) {
                                        if (MMonit_send(e) != Handler_Mmonit) {
                                                e->flag &= ~Handler_Mmonit;
                                                Run.handler_queue[Handler_Mmonit]--;
                                                handlers_passed++;
                                        } else {
                                                Log_error("M/Monit handler failed, retry scheduled for next cycle\n");
                                                Run.handler_flag |= Handler_Mmonit;
                                        }
                                }
                        }

                        /* If no error persists, remove it from the queue */
                        if (e->flag == Handler_Succeeded) {
                                DEBUG("Removing queued event %s\n", file_name);
                                if (unlink(file_name) < 0)
                                        Log_error("Failed to remove queued event file '%s' -- %s\n", file_name, STRERROR);
                        } else if (handlers_passed > 0) {
                                DEBUG("Updating queued event %s (some handlers passed)\n", file_name);
                                _queueUpdate(e, file_name);
                        }

                error6:
                        FREE(action);
                error5:
                        FREE(e->message);
                error4:
                        FREE(e);
                error3:
                        FREE(version);
                error2:
                        fclose(file);
                }
        error1:
                de = readdir(dir);
        }
        Run.flags &= ~Run_HandlerInit;
        closedir(dir);
        FREE(a);
        FREE(ea);
}

