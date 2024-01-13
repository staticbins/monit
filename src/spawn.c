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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
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

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#include "event.h"
#include "alert.h"
#include "monit.h"
#include "engine.h"

#include "spawn.h"

// libmonit
#include "io/File.h"
#include "util/Str.h"
#include "util/Fmt.h"
#include "system/Time.h"
#include "system/Command.h"
#include "exceptions/AssertException.h"


pid_t spawn(spawn_args_t args) {
        assert(args);
        assert(args->S);
        assert(args->cmd);
        pid_t status = -1;
        // Required
        Service_T S = args->S;
        command_t cmd = args->cmd;
        // Optional
        char *err = args->err;
        int errlen = args->errlen;
        Event_T E = args->E;
        // Check first if the program still exist (could have been removed while Monit was up)
        if (! File_exist(cmd->arg[0])) {
                if (err)
                        snprintf(err, errlen, "File to execute '%s' no longer exist\n",  cmd->arg[0]);
                else
                        Log_error("Error: File to execute '%s' no longer exist\n", cmd->arg[0]);
                return -1;
        }
        Command_T C = Command_new(cmd->arg[0]);
        assert(C);
        for (int i = 1; i < cmd->length; i++)
                Command_appendArgument(C, cmd->arg[i]);
        if (cmd->has_uid)
                Command_setUid(C, cmd->uid);
        if (cmd->has_gid)
                Command_setGid(C, cmd->gid);
        // Setup the environment with special MONIT_xxx variables. The program
        // executed may use such variable for various purposes.
        Command_setEnv(C, "MONIT_DATE", Time_localStr(Time_now(), (char[26]){}));
        Command_setEnv(C, "MONIT_SERVICE", S->name);
        Command_setEnv(C, "MONIT_HOST", Run.system->name);
        Command_setEnv(C, "MONIT_EVENT", E ? Event_get_description(E) : cmd == S->start ? "Started" : cmd == S->stop ? "Stopped" : "No Event");
        Command_setEnv(C, "MONIT_DESCRIPTION", E ? E->message : cmd == S->start ? "Started" : cmd == S->stop ? "Stopped" : "No Event");
        switch (S->type) {
                case Service_Process:
                        Command_vSetEnv(C, "MONIT_PROCESS_PID", "%d", S->inf.process->pid);
                        Command_vSetEnv(C, "MONIT_PROCESS_MEMORY", "%llu", (unsigned long long)((double)S->inf.process->mem / 1024.));
                        Command_vSetEnv(C, "MONIT_PROCESS_CHILDREN", "%d", S->inf.process->children);
                        Command_vSetEnv(C, "MONIT_PROCESS_CPU_PERCENT", "%.1f", S->inf.process->cpu_percent);
                        break;
                case Service_Program:
                        Command_vSetEnv(C, "MONIT_PROGRAM_STATUS", "%d", S->program->exitStatus);
                        break;
                default:
                        break;
        }
        Process_T P = Command_execute(C);
        if (P) {
                status = Process_pid(P);
                Process_setName(P, S->name);
                ProcessTable_setProcess(Process_Table, P);
        } else {
                if (err)
                        snprintf(err, errlen, "Failed to execute '%s'  -- %s", cmd->arg[0], System_lastError());
                else
                        Log_error("Error: Failed to execute '%s' -- %s\n", cmd->arg[0], System_lastError());
        }
        Command_free(&C);
        return status;
}

