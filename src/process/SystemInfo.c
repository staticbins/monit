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
#include "ProcessTree.h"
#include "process_sysdep.h"
#include "SystemInfo.h"


/**
 *  Initialize and update the global SystemInfo structure
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


bool SystemInfo_init(void) {
        memset(&systeminfo, 0, sizeof(SystemInfo_T));
        gettimeofday(&systeminfo.collected, NULL);
        if (uname(&systeminfo.uname) < 0) {
                Log_error("'%s' resource monitoring initialization error -- uname failed: %s\n", Run.system->name, STRERROR);
                return false;
        }
        systeminfo.cpu.usage.user = -1.;
        systeminfo.cpu.usage.system = -1.;
        systeminfo.cpu.usage.iowait = -1.;
        return (init_systeminfo_sysdep());
}


bool SystemInfo_update(void) {
        if (getloadavg_sysdep(systeminfo.loadavg, 3) == -1) {
                Log_error("'%s' statistic error -- load average data collection failed\n", Run.system->name);
                goto error1;
        }
        if (! used_system_memory_sysdep(&systeminfo)) {
                Log_error("'%s' statistic error -- memory usage data collection failed\n", Run.system->name);
                goto error2;
        }
        systeminfo.memory.usage.percent  = systeminfo.memory.size > 0ULL ? (100. * (double)systeminfo.memory.usage.bytes / (double)systeminfo.memory.size) : 0.;
        systeminfo.swap.usage.percent = systeminfo.swap.size > 0ULL ? (100. * (double)systeminfo.swap.usage.bytes / (double)systeminfo.swap.size) : 0.;
        if (! used_system_cpu_sysdep(&systeminfo)) {
                Log_error("'%s' statistic error -- cpu usage data collection failed\n", Run.system->name);
                goto error3;
        }
        if (! used_system_filedescriptors_sysdep(&systeminfo)) {
                Log_error("'%s' statistic error -- filedescriptors usage data collection failed\n", Run.system->name);
                goto error4;
        }
        return true;
error1:
        systeminfo.loadavg[0] = 0;
        systeminfo.loadavg[1] = 0;
        systeminfo.loadavg[2] = 0;
error2:
        systeminfo.memory.usage.bytes = 0ULL;
        systeminfo.memory.usage.percent = 0.;
        systeminfo.swap.usage.bytes = 0ULL;
        systeminfo.swap.usage.percent = 0.;
error3:
        systeminfo.cpu.usage.user = 0.;
        systeminfo.cpu.usage.system = 0.;
        systeminfo.cpu.usage.iowait = 0.;
error4:
        systeminfo.filedescriptors.allocated = 0LL;
        systeminfo.filedescriptors.unused = 0LL;
        systeminfo.filedescriptors.maximum = 0LL;
        return false;
}


