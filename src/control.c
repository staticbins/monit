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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "monit.h"
#include "spawn.h"
#include "Proc.h"
#include "event.h"
#include "util.h"
#include "control.h"

// libmonit
#include "io/File.h"
#include "util/Fmt.h"
#include "system/Time.h"
#include "exceptions/AssertException.h"


/**
 *  Methods for controlling services managed by monit.
 *
 *  @file
 */


// TODO: Refactor all attempts to wait on anything. Instead continous check
// should be handled non-blocking in the validate state-machine

/* ------------------------------------------------------------- Definitions */


typedef enum {
        Process_Stopped = 0,
        Process_Started
} Process_Status;


#define RETRY_INTERVAL 100000 // 100ms


/* ----------------------------------------------------------------- Private */


// TODO: Remove, will be replaced by state-machine
static Process_Status _waitProcessStart(Service_T s, long long *timeout) {
        long wait = RETRY_INTERVAL;
        do {
                Time_usleep(wait);
                pid_t pid = ProcessTable_findServiceProcess(s);
                if (pid) {
                        if (ProcessTable_update(Process_Table))
                                ProcessTable_updateServiceProcess(Process_Table, s, pid);
                        return Process_Started;
                }
                *timeout -= wait;
                wait = wait < 1000000 ? wait * 2 : 1000000; // double the wait during each cycle until 1s is reached (ProcessTable_findProcess() can be heavy and we don't want to drain power every 100ms on mobile devices)
        } while (*timeout > 0 && ! (Run.flags & Run_Stopped));
        return Process_Stopped;
}


// TODO: Remove, will be replaced by state-machine
static Process_Status _waitProcessStop(int pid, long long *timeout) {
        do {
                Time_usleep(RETRY_INTERVAL);
                if (!ProcessTable_exist(pid))
                        return Process_Stopped;
                *timeout -= RETRY_INTERVAL;
        } while (*timeout > 0 && ! (Run.flags & Run_Stopped));
        return Process_Started;
}


// TODO: Remove, will be replaced by state-machine
static Check_State _check(Service_T s) {
        assert(s);
        Check_State rv = Check_Succeeded;
        // The check is performed in passive mode - we want to just check, nested start/stop/restart action is unwanted (alerts are allowed so the user will get feedback what's wrong)
        Monitor_Mode original = s->mode;
        s->mode = Monitor_Passive;
        rv = s->check(s);
        if (s->type == Service_Program && s->program->P) {
                // check program executes the program and needs to be called again to collect the exit value and evaluate the status
                long long timeout = s->program->timeout * USEC_PER_MSEC;
                do {
                        Time_usleep(RETRY_INTERVAL);
                        timeout -= RETRY_INTERVAL;
                } while (Process_exitStatus(s->program->P) < 0 && timeout > 0LL && ! (Run.flags & Run_Stopped));
                rv = s->check(s);
        }
        s->mode = original;
        return rv;
}


/*
 * This is a post-fix recursive function for starting every service
 * that s depends on before starting s.
 * @param s A Service_T object
 * @return true if the service was started otherwise false
 */
static bool _doStart(Service_T s) {
        assert(s);
        bool rv = true;
        StringBuffer_T sb = StringBuffer_create(64);
        for (Dependant_T d = s->dependantlist; d; d = d->next ) {
                Service_T parent = Util_getService(d->dependant);
                assert(parent);
                if (parent->monitor != Monitor_Yes || parent->error) {
                        if (_doStart(parent)) {
                                Check_State state = _check(parent);
                                if (state != Check_Failed && state != Check_Init)
                                        continue;
                        }
                        rv = false;
                        StringBuffer_append(sb, "%s%s", StringBuffer_length(sb) ? ", " : "", parent->name);
                }
        }
        if (rv) {
                if (s->start) {
                        if (s->type != Service_Process || ! ProcessTable_findServiceProcess(s)) {
                                Log_info("'%s' start: '%s'\n", s->name, Util_commandDescription(s->start, (char[STRLEN]){}));
                                char msg[1024];
                                long long timeout = s->start->timeout * USEC_PER_MSEC;
                                pid_t status = spawn(&(struct spawn_args_t){
                                        .S = s,
                                        .cmd = s->start,
                                        .err = msg,
                                        .errlen = sizeof(msg)
                                });
                                if (status < 0 || (s->type == Service_Process && _waitProcessStart(s, &timeout) != Process_Started)) {
                                        Event_post(s, Event_Exec, Check_Failed, s->action_EXEC, "failed to start (exit status %d) -- %s", errno, *msg ? msg : "no output");
                                        rv = false;
                                } else {
                                        Event_post(s, Event_Exec, Check_Succeeded, s->action_EXEC, "started (pid = %d)", status);
                                }
                        }
                } else {
                        Log_debug("'%s' start method not defined\n", s->name);
                        Event_post(s, Event_Exec, Check_Succeeded, s->action_EXEC, "monitoring enabled");
                }
        } else {
                Event_post(s, Event_Exec, Check_Failed, s->action_EXEC, "failed to start -- could not start required services: '%s'", StringBuffer_toString(sb));
                s->doaction = Action_Start; // Retry the start next cycle
        }
        Util_monitorSet(s);
        StringBuffer_free(&sb);
        return rv;
}


static int _executeStop(Service_T s, char *msg, int msglen, long long *timeout) {
        Log_info("'%s' stop: '%s'\n", s->name, Util_commandDescription(s->stop, (char[STRLEN]){}));
        return spawn(&(struct spawn_args_t){
                .S = s,
                .cmd = s->stop,
                .err = msg,
                .errlen = msglen
        });
}


static void _evaluateStop(Service_T s, bool succeeded, int exitStatus, char *msg) {
        if (succeeded)
                Event_post(s, Event_Exec, Check_Succeeded, s->action_EXEC, "stopped");
        else
                Event_post(s, Event_Exec, Check_Failed, s->action_EXEC, "failed to stop (exit status %d) -- %s", errno, *msg ? msg : "no output");
}


/*
 * This function simply stops the service s.
 * @param s A Service_T object
 * @param unmonitor true if the monitoring should be disabled or false if monitoring should continue (when stop is part of restart)
 * @return true if the service was stopped otherwise false
 */
static bool _doStop(Service_T s, bool unmonitor) {
        assert(s);
        bool rv = true;
        if (s->stop) {
                if (s->monitor != Monitor_Not) {
                        int exitStatus;
                        char msg[1024];
                        long long timeout = s->stop->timeout * USEC_PER_MSEC;
                        if (s->type == Service_Process) {
                                int pid = ProcessTable_findServiceProcess(s);
                                if (pid) {
                                        exitStatus = _executeStop(s, msg, sizeof(msg), &timeout);
                                        rv = _waitProcessStop(pid, &timeout) == Process_Stopped ? true : false;
                                        _evaluateStop(s, rv, exitStatus, msg);
                                }
                        } else {
                                exitStatus = _executeStop(s, msg, sizeof(msg), &timeout);
                                rv = exitStatus >= 0 ? true : false;
                                _evaluateStop(s, rv, exitStatus, msg);
                        }
                }
        } else {
                Log_debug("'%s' stop skipped -- method not defined\n", s->name);
        }
        if (unmonitor) {
                Util_monitorUnset(s);
        } else {
                Util_resetInfo(s);
                s->monitor = Monitor_Init;
        }
        return rv;
}


/*
 * This function simply restarts the service s.
 * @param s A Service_T object
 */
static bool _doRestart(Service_T s) {
        assert(s);
        bool rv = true;
        if (s->restart) {
                Log_info("'%s' restart: '%s'\n", s->name, Util_commandDescription(s->restart, (char[STRLEN]){}));
                Util_resetInfo(s);
                char msg[1024];
                long long timeout = s->restart->timeout * USEC_PER_MSEC;
                pid_t status = spawn(&(struct spawn_args_t){
                        .S = s,
                        .cmd = s->restart,
                        .err = msg,
                        .errlen = sizeof(msg)
                });
                if (status < 0 || (s->type == Service_Process && _waitProcessStart(s, &timeout) != Process_Started)) {
                        rv = false;
                        Event_post(s, Event_Exec, Check_Failed, s->action_EXEC, "failed to restart (exit status %d) -- %s", status, msg);
                } else {
                        Event_post(s, Event_Exec, Check_Succeeded, s->action_EXEC, "restarted (pid=%d)", status);
                }
        } else {
                Log_debug("'%s' restart skipped -- method not defined\n", s->name);
        }
        Util_monitorSet(s);
        return rv;
}


/*
 * This is a post- fix recursive function for enabling monitoring every service
 * that s depends on before monitor s.
 * @param s A Service_T object
 */
static void _doMonitor(Service_T s) {
        assert(s);
        for (Dependant_T d = s->dependantlist; d; d = d->next ) {
                Service_T parent = Util_getService(d->dependant);
                assert(parent);
                _doMonitor(parent);
        }
        Util_monitorSet(s);
}


/*
 * This is a function for disabling monitoring
 * @param s A Service_T object
 */
static void _doUnmonitor(Service_T s) {
        assert(s);
        Util_monitorUnset(s);
}


/*
 * This is an in-fix recursive function for control of services that depend on s
 * @param s A Service_T object
 * @param action An action for the dependant services
 * @param unmonitor Disable service monitoring: used for stop action only to differentiate hard/soft stop - see _doStop()
 * @return true if all depending services were started/stopped otherwise false
 */
static bool _doDepend(Service_T s, Action_Type action, bool unmonitor) {
        assert(s);
        bool rv = true;
        for (Service_T child = Service_List; child; child = child->next) {
                for (Dependant_T d = child->dependantlist; d; d = d->next) {
                        if (IS(d->dependant, s->name)) {
                                if (action == Action_Start) {
                                        // (re)start children only if it's monitoring is enabled (we keep monitoring flag during restart, allowing to restore original pre-restart configuration)
                                        if (child->monitor != Monitor_Not && ! _doStart(child))
                                                rv = false;
                                } else if (action == Action_Monitor) {
                                        _doMonitor(child);
                                }
                                // We can start children of current child (2nd+ dependency level) only if the child itself started
                                if (rv) {
                                        if (! _doDepend(child, action, unmonitor)) {
                                                rv = false;
                                        } else {
                                                // Stop this service only if all children stopped
                                                if (action == Action_Stop && child->monitor != Monitor_Not) {
                                                        if (! _doStop(child, unmonitor))
                                                                rv = false;
                                                } else if (action == Action_Unmonitor) {
                                                        _doUnmonitor(child);
                                                }
                                        }
                                }
                                if (child->doaction == action) {
                                        child->doaction = Action_Ignored;
                                }
                                break;
                        }
                }
        }
        return rv;
}




/* ------------------------------------------------------------------ Public */


/**
 * Apply given action to the services list.
 * @param services A services list
 * @param action A string describing the action to execute
 * @return number of errors
 */
bool control_service_string(List_T services, const char *action) {
        assert(services);
        assert(action);
        Action_Type a = Util_getAction(action);
        if (a == Action_Ignored) {
                Log_error("invalid action %s\n", action);
                return 1;
        }
        int errors = 0;
        for (list_t s = services->head; s; s = s->next)
                if (control_service(s->e, a) == false)
                        errors++;
        return errors;
}


/**
 * Check to see if we should try to start/stop service
 * @param S A service name as stated in the config file
 * @param A An action id describing the action to execute
 * @return false for error, otherwise true
 */
bool control_service(const char *S, Action_Type A) {
        Service_T s = NULL;
        bool rv = true;
        assert(S);
        if (! (s = Util_getService(S))) {
                Log_error("Service '%s' -- doesn't exist\n", S);
                return false;
        }
        switch (A) {
                case Action_Start:
                        rv = _doStart(s);
                        break;

                case Action_Stop:
                        // Stop this service only if all children which depend on it were stopped
                        if (_doDepend(s, Action_Stop, true))
                                rv = _doStop(s, true);
                        break;

                case Action_Restart:
                        Log_info("'%s' trying to restart\n", s->name);
                        // Restart this service only if all children that depend on it were stopped
                        if (_doDepend(s, Action_Stop, false)) {
                                if (s->restart) {
                                        if ((rv = _doRestart(s)))
                                                _doDepend(s, Action_Start, false); // Start children only if we successfully restarted
                                } else {
                                        if (_doStop(s, false)) {
                                                if ((rv = _doStart(s))) // Only start if we successfully stopped
                                                        _doDepend(s, Action_Start, false); // Start children only if we successfully started
                                        } else {
                                                /* enable monitoring of this service again to allow the restart retry in the next cycle up to timeout limit */
                                                Util_monitorSet(s);
                                        }
                                }
                        }
                        break;

                case Action_Monitor:
                        /* We only enable monitoring of this service and all prerequisite services. Chain of services which depends on this service keeps its state */
                        _doMonitor(s);
                        break;

                case Action_Unmonitor:
                        /* We disable monitoring of this service and all services which depends on it */
                        _doDepend(s, Action_Unmonitor, false);
                        _doUnmonitor(s);
                        break;

                default:
                        Log_error("Service '%s' -- invalid action %d\n", S, A);
                        rv = false;
        }
        if (s->doaction == A) {
                s->doaction = Action_Ignored;
        }
        return rv;
}

