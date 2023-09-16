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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include "monit.h"
#include "ProcessTable.h"
#include "process_sysdep.h"
#include "SystemInfo.h"


/**
 *  Initialize and update the global SystemInfo structure
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


bool SystemInfo_init(void) {
        memset(&System_Info, 0, sizeof(SystemInfo_T));
        gettimeofday(&System_Info.collected, NULL);
        if (uname(&System_Info.uname) < 0) {
                Log_error("'%s' resource monitoring initialization error -- uname failed: %s\n", Run.system->name, STRERROR);
                return false;
        }
        System_Info.cpu.usage.user = -1.;
        System_Info.cpu.usage.system = -1.;
        System_Info.cpu.usage.iowait = -1.;
        return (init_systeminfo_sysdep());
}


bool SystemInfo_update(void) {
        if (getloadavg_sysdep(System_Info.loadavg, 3) == -1) {
                Log_error("'%s' statistic error -- load average data collection failed\n", Run.system->name);
                goto error1;
        }
        if (! used_system_memory_sysdep(&System_Info)) {
                Log_error("'%s' statistic error -- memory usage data collection failed\n", Run.system->name);
                goto error2;
        }
        System_Info.memory.usage.percent  = System_Info.memory.size > 0ULL ? (100. * (double)System_Info.memory.usage.bytes / (double)System_Info.memory.size) : 0.;
        System_Info.swap.usage.percent = System_Info.swap.size > 0ULL ? (100. * (double)System_Info.swap.usage.bytes / (double)System_Info.swap.size) : 0.;
        if (! used_system_cpu_sysdep(&System_Info)) {
                Log_error("'%s' statistic error -- cpu usage data collection failed\n", Run.system->name);
                goto error3;
        }
        if (! used_system_filedescriptors_sysdep(&System_Info)) {
                Log_error("'%s' statistic error -- filedescriptors usage data collection failed\n", Run.system->name);
                goto error4;
        }
        return true;
error1:
        System_Info.loadavg[0] = 0;
        System_Info.loadavg[1] = 0;
        System_Info.loadavg[2] = 0;
error2:
        System_Info.memory.usage.bytes = 0ULL;
        System_Info.memory.usage.percent = 0.;
        System_Info.swap.usage.bytes = 0ULL;
        System_Info.swap.usage.percent = 0.;
error3:
        System_Info.cpu.usage.user = 0.;
        System_Info.cpu.usage.system = 0.;
        System_Info.cpu.usage.iowait = 0.;
error4:
        System_Info.filedescriptors.allocated = 0LL;
        System_Info.filedescriptors.unused = 0LL;
        System_Info.filedescriptors.maximum = 0LL;
        return false;
}


