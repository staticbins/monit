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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ASM_PARAM_H
#include <asm/param.h>
#endif

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

#ifdef HAVE_SYS_SYSINFO_H
#include <sys/sysinfo.h>
#endif

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include "monit.h"
#include "ProcessTree.h"
#include "process_sysdep.h"

// libmonit
#include "system/Time.h"

/**
 *  System dependent resource data collection code for Linux.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


static struct {
        int hasIOStatistics; // True if /proc/<PID>/io is present
} _statistics = {};


typedef struct Proc_T {
        StringBuffer_T name;
        struct {
                int                 pid;
                int                 ppid;
                int                 uid;
                int                 euid;
                int                 gid;
                char                item_state;
                long                item_cutime;
                long                item_cstime;
                long                item_rss;
                int                 item_threads;
                unsigned long       item_utime;
                unsigned long       item_stime;
                unsigned long long  item_starttime;
                struct {
                        unsigned long long    bytes;
                        unsigned long long    bytesPhysical;
                        unsigned long long    operations;
                } read;
                struct {
                        unsigned long long    bytes;
                        unsigned long long    bytesPhysical;
                        unsigned long long    operations;
                } write;
                struct {
                        long long     open;
                        struct {
                                long long soft;
                                long long hard;
                        } limit;
                } filedescriptors;
                char                secattr[STRLEN];
        } data;
} *Proc_T;


/* --------------------------------------- Static constructor and destructor */


static void __attribute__ ((constructor)) _constructor(void) {
        struct stat sb;
        _statistics.hasIOStatistics = stat("/proc/self/io", &sb) == 0 ? true : false;
}


/* ----------------------------------------------------------------- Private */


#define NSEC_PER_SEC    1000000000L

static unsigned long long old_cpu_user       = 0;
static unsigned long long old_cpu_nice       = 0;
static unsigned long long old_cpu_syst       = 0;
static unsigned long long old_cpu_iowait     = 0;
static unsigned long long old_cpu_hardirq    = 0;
static unsigned long long old_cpu_softirq    = 0;
static unsigned long long old_cpu_steal      = 0;
static unsigned long long old_cpu_guest      = 0;
static unsigned long long old_cpu_guest_nice = 0;
static unsigned long long old_cpu_total      = 0;

static long page_size = 0;

static double hz = 0.;

/**
 * Get system start time
 * @return seconds since unix epoch
 */
static time_t _getStartTime(void) {
        struct sysinfo info;
        if (sysinfo(&info) < 0) {
                LogError("system statistic error -- cannot get system uptime: %s\n", STRERROR);
                return 0;
        }
        return Time_now() - info.uptime;
}


// parse /proc/PID/stat
static bool _parseProcPidStat(Proc_T proc) {
        char buf[8192];
        char *tmp = NULL;
        if (! file_readProc(buf, sizeof(buf), "stat", proc->data.pid, NULL)) {
                DEBUG("system statistic error -- cannot read /proc/%d/stat\n", proc->data.pid);
                return false;
        }
        // Skip the process name (can have multiple words)
        if (! (tmp = strrchr(buf, ')'))) {
                DEBUG("system statistic error -- file /proc/%d/stat parse error\n", proc->data.pid);
                return false;
        }
        if (sscanf(tmp + 2,
                   "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %ld %ld %*d %*d %d %*u %llu %*u %ld %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*d %*d\n",
                   &(proc->data.item_state),
                   &(proc->data.ppid),
                   &(proc->data.item_utime),
                   &(proc->data.item_stime),
                   &(proc->data.item_cutime),
                   &(proc->data.item_cstime),
                   &(proc->data.item_threads),
                   &(proc->data.item_starttime),
                   &(proc->data.item_rss)) != 9) {
                DEBUG("system statistic error -- file /proc/%d/stat parse error\n", proc->data.pid);
                return false;
        }
        return true;
}


// parse /proc/PID/status
static bool _parseProcPidStatus(Proc_T proc) {
        char buf[4096];
        char *tmp = NULL;
        if (! file_readProc(buf, sizeof(buf), "status", proc->data.pid, NULL)) {
                DEBUG("system statistic error -- cannot read /proc/%d/status\n", proc->data.pid);
                return false;
        }
        if (! (tmp = strstr(buf, "Uid:"))) {
                DEBUG("system statistic error -- cannot find process uid\n");
                return false;
        }
        if (sscanf(tmp + 4, "\t%d\t%d", &(proc->data.uid), &(proc->data.euid)) != 2) {
                DEBUG("system statistic error -- cannot read process uid\n");
                return false;
        }
        if (! (tmp = strstr(buf, "Gid:"))) {
                DEBUG("system statistic error -- cannot find process gid\n");
                return false;
        }
        if (sscanf(tmp + 4, "\t%d", &(proc->data.gid)) != 1) {
                DEBUG("system statistic error -- cannot read process gid\n");
                return false;
        }
        return true;
}


// parse /proc/PID/io
static bool _parseProcPidIO(Proc_T proc) {
        char buf[4096];
        char *tmp = NULL;
        if (_statistics.hasIOStatistics) {
                if (file_readProc(buf, sizeof(buf), "io", proc->data.pid, NULL)) {
                        // read bytes (total)
                        if (! (tmp = strstr(buf, "rchar:"))) {
                                DEBUG("system statistic error -- cannot find process read bytes\n");
                                return false;
                        }
                        if (sscanf(tmp + 6, "\t%llu", &(proc->data.read.bytes)) != 1) {
                                DEBUG("system statistic error -- cannot get process read bytes\n");
                                return false;
                        }
                        // write bytes (total)
                        if (! (tmp = strstr(tmp, "wchar:"))) {
                                DEBUG("system statistic error -- cannot find process write bytes\n");
                                return false;
                        }
                        if (sscanf(tmp + 6, "\t%llu", &(proc->data.write.bytes)) != 1) {
                                DEBUG("system statistic error -- cannot get process write bytes\n");
                                return false;
                        }
                        // read operations
                        if (! (tmp = strstr(tmp, "syscr:"))) {
                                DEBUG("system statistic error -- cannot find process read system calls count\n");
                                return false;
                        }
                        if (sscanf(tmp + 6, "\t%llu", &(proc->data.read.operations)) != 1) {
                                DEBUG("system statistic error -- cannot get process read system calls count\n");
                                return false;
                        }
                        // write operations
                        if (! (tmp = strstr(tmp, "syscw:"))) {
                                DEBUG("system statistic error -- cannot find process write system calls count\n");
                                return false;
                        }
                        if (sscanf(tmp + 6, "\t%llu", &(proc->data.write.operations)) != 1) {
                                DEBUG("system statistic error -- cannot get process write system calls count\n");
                                return false;
                        }
                        // read bytes (physical I/O)
                        if (! (tmp = strstr(tmp, "read_bytes:"))) {
                                DEBUG("system statistic error -- cannot find process physical read bytes\n");
                                return false;
                        }
                        if (sscanf(tmp + 11, "\t%llu", &(proc->data.read.bytesPhysical)) != 1) {
                                DEBUG("system statistic error -- cannot get process physical read bytes\n");
                                return false;
                        }
                        // write bytes (physical I/O)
                        if (! (tmp = strstr(tmp, "write_bytes:"))) {
                                DEBUG("system statistic error -- cannot find process physical write bytes\n");
                                return false;
                        }
                        if (sscanf(tmp + 12, "\t%llu", &(proc->data.write.bytesPhysical)) != 1) {
                                DEBUG("system statistic error -- cannot get process physical write bytes\n");
                                return false;
                        }
                } else {
                        // file_readProc() already printed a DEBUG() message
                        return false;
                }
        }
        return true;
}


// parse /proc/PID/cmdline
static bool _parseProcPidCmdline(Proc_T proc, ProcessEngine_Flags pflags) {
        if (pflags & ProcessEngine_CollectCommandLine) {
                char filename[STRLEN];
                // Try to collect the command-line from the procfs cmdline (user-space processes)
                snprintf(filename, sizeof(filename), "/proc/%d/cmdline", proc->data.pid);
                FILE *f = fopen(filename, "r");
                if (! f) {
                        DEBUG("system statistic error -- cannot open /proc/%d/cmdline: %s\n", proc->data.pid, STRERROR);
                        return false;
                }
                size_t n;
                char buf[STRLEN] = {};
                while ((n = fread(buf, 1, sizeof(buf) - 1, f)) > 0) {
                        // The cmdline file contains argv elements/strings separated by '\0' => join the string
                        for (size_t i = 0; i < n; i++) {
                                if (buf[i] == 0)
                                        StringBuffer_append(proc->name, " ");
                                else
                                        StringBuffer_append(proc->name, "%c", buf[i]);
                        }
                }
                fclose(f);
                // Fallback to procfs stat process name if cmdline was empty (even kernel-space processes have information here)
                if (! StringBuffer_length(proc->name)) {
                        char buffer[8192];
                        char *tmp = NULL;
                        char *procname = NULL;
                        if (! file_readProc(buffer, sizeof(buffer), "stat", proc->data.pid, NULL)) {
                                DEBUG("system statistic error -- cannot read /proc/%d/stat\n", proc->data.pid);
                                return false;
                        }
                        if (! (tmp = strrchr(buffer, ')'))) {
                                DEBUG("system statistic error -- file /proc/%d/stat parse error\n", proc->data.pid);
                                return false;
                        }
                        *tmp = 0;
                        if (! (procname = strchr(buffer, '('))) {
                                DEBUG("system statistic error -- file /proc/%d/stat parse error\n", proc->data.pid);
                                return false;
                        }
                        StringBuffer_append(proc->name, "%s", procname + 1);
                }
        }
        return true;
}


// parse /proc/PID/attr/current
static bool _parseProcPidAttrCurrent(Proc_T proc) {
        if (file_readProc(proc->data.secattr, sizeof(proc->data.secattr), "attr/current", proc->data.pid, NULL)) {
                Str_trim(proc->data.secattr);
                return true;
        }
        return false;
}

// count entries in /proc/PID/fd
static bool _parseProcFdCount(Proc_T proc) {
        char path[PATH_MAX] = {};
        unsigned long long file_count = 0;

        snprintf(path, sizeof(path), "/proc/%d/fd", proc->data.pid);
        DIR *dirp = opendir(path);
        if (! dirp) {
                DEBUG("system statistic error -- opendir %s: %s\n", path, STRERROR);
                return false;
        }
        errno = 0;
        while (readdir(dirp) != NULL) {
                // count everything
                file_count++;
        }
        // do not closedir() until readdir errno has been evaluated
        if (errno) {
                DEBUG("system statistic error -- cannot iterate %s: %s\n", path, STRERROR);
                closedir(dirp);
                return false;
        }
        closedir(dirp);
        // assert at least '.' and '..' have been found
        if (file_count < 2) {
                DEBUG("system statistic error -- cannot find basic entries in %s\n", path);
                return false;
        }
        // subtract entries '.' and '..'
        proc->data.filedescriptors.open = file_count - 2;

        // get process's limits
#ifdef HAVE_PRLIMIT
        struct rlimit limits;
        if (prlimit(proc->data.pid, RLIMIT_NOFILE, NULL, &limits) != 0) {
                DEBUG("prlimit failed: %s\n", STRERROR);
                return false;
        }
        proc->data.filedescriptors.limit.soft = limits.rlim_cur;
        proc->data.filedescriptors.limit.hard = limits.rlim_max;
#else
        // Try to collect the command-line from the procfs cmdline (user-space processes)
        snprintf(path, sizeof(path), "/proc/%d/limits", proc->data.pid);
        FILE *f = fopen(path, "r");
        if (f) {
                int softLimit;
                int hardLimit;
                char line[STRLEN];
                while (fgets(line, sizeof(line), f)) {
                        if (sscanf(line, "Max open files %d %d", &softLimit, &hardLimit) == 2) {
                                proc->data.filedescriptors.limit.soft = softLimit;
                                proc->data.filedescriptors.limit.hard = hardLimit;
                                break;
                        }
                }
                fclose(f);
        } else {
                DEBUG("system statistic error -- cannot open %s\n", path);
                return false;
        }
#endif

        return true;
}

static double _usagePercent(unsigned long long previous, unsigned long long current, double total) {
        if (current < previous) {
                // The counter jumped back (observed for cpu wait metric on Linux 4.15) or wrapped
                return 0.;
        }
        return (double)(current - previous) / total * 100.;
}


/* ------------------------------------------------------------------ Public */


bool init_process_info_sysdep(void) {
        if ((hz = sysconf(_SC_CLK_TCK)) <= 0.) {
                DEBUG("system statistic error -- cannot get hz: %s\n", STRERROR);
                return false;
        }

        if ((page_size = sysconf(_SC_PAGESIZE)) <= 0) {
                DEBUG("system statistic error -- cannot get page size: %s\n", STRERROR);
                return false;
        }

        if ((systeminfo.cpu.count = sysconf(_SC_NPROCESSORS_CONF)) < 0) {
                DEBUG("system statistic error -- cannot get cpu count: %s\n", STRERROR);
                return false;
        } else if (systeminfo.cpu.count == 0) {
                DEBUG("system reports cpu count 0, setting dummy cpu count 1\n");
                systeminfo.cpu.count = 1;
        }

        FILE *f = fopen("/proc/meminfo", "r");
        if (f) {
                char line[STRLEN];
                systeminfo.memory.size = 0L;
                while (fgets(line, sizeof(line), f)) {
                        if (sscanf(line, "MemTotal: %llu", &systeminfo.memory.size) == 1) {
                                systeminfo.memory.size *= 1024;
                                break;
                        }
                }
                fclose(f);
                if (! systeminfo.memory.size)
                        DEBUG("system statistic error -- cannot get real memory amount\n");
        } else {
                DEBUG("system statistic error -- cannot open /proc/meminfo\n");
        }

        f = fopen("/proc/stat", "r");
        if (f) {
                char line[STRLEN];
                systeminfo.booted = 0;
                while (fgets(line, sizeof(line), f)) {
                        if (sscanf(line, "btime %llu", &systeminfo.booted) == 1) {
                                break;
                        }
                }
                fclose(f);
                if (! systeminfo.booted)
                        DEBUG("system statistic error -- cannot get system boot time\n");
        } else {
                DEBUG("system statistic error -- cannot open /proc/stat\n");
        }

        return true;
}


/**
 * Read all processes of the proc files system to initialize the process tree
 * @param reference reference of ProcessTree
 * @param pflags Process engine flags
 * @return treesize > 0 if succeeded otherwise 0
 */
int initprocesstree_sysdep(ProcessTree_T **reference, ProcessEngine_Flags pflags) {
        ASSERT(reference);

        // Find all processes in the /proc directory
        glob_t globbuf;
        int rv = glob("/proc/[0-9]*", 0, NULL, &globbuf);
        if (rv) {
                LogError("system statistic error -- glob failed: %d (%s)\n", rv, STRERROR);
                return 0;
        }
        ProcessTree_T *pt = CALLOC(sizeof(ProcessTree_T), globbuf.gl_pathc);


        int count = 0;
        struct Proc_T proc = {
                .name = StringBuffer_create(64)
        };
        time_t starttime = _getStartTime();
        for (size_t i = 0; i < globbuf.gl_pathc; i++) {
                proc.data.pid = atoi(globbuf.gl_pathv[i] + 6); // skip "/proc/"
                if (_parseProcPidStat(&proc) && _parseProcPidStatus(&proc) && _parseProcPidIO(&proc) && _parseProcPidCmdline(&proc, pflags) && _parseProcFdCount(&proc)) {
                        // Non-mandatory statistics (may not exist)
                        _parseProcPidAttrCurrent(&proc);
                        // Set the data in ptree only if all process related reads succeeded (prevent partial data in the case that continue was called during data collecting)
                        pt[count].pid = proc.data.pid;
                        pt[count].ppid = proc.data.ppid;
                        pt[count].cred.uid = proc.data.uid;
                        pt[count].cred.euid = proc.data.euid;
                        pt[count].cred.gid = proc.data.gid;
                        pt[count].threads.self = proc.data.item_threads;
                        pt[count].uptime = starttime > 0 ? (systeminfo.time / 10. - (starttime + (time_t)(proc.data.item_starttime / hz))) : 0;
                        pt[count].cpu.time = (double)(proc.data.item_utime + proc.data.item_stime) / hz * 10.; // jiffies -> seconds = 1/hz
                        pt[count].memory.usage = (unsigned long long)proc.data.item_rss * (unsigned long long)page_size;
                        pt[count].read.bytes = proc.data.read.bytes;
                        pt[count].read.bytesPhysical = proc.data.read.bytesPhysical;
                        pt[count].read.operations = proc.data.read.operations;
                        pt[count].write.bytes = proc.data.write.bytes;
                        pt[count].write.bytesPhysical = proc.data.write.bytesPhysical;
                        pt[count].write.operations = proc.data.write.operations;
                        pt[count].read.time = pt[count].write.time = Time_milli();
                        pt[count].zombie = proc.data.item_state == 'Z' ? true : false;
                        pt[count].cmdline = Str_dup(StringBuffer_toString(proc.name));
                        pt[count].secattr = Str_dup(proc.data.secattr);
                        pt[count].filedescriptors.usage = proc.data.filedescriptors.open;
                        pt[count].filedescriptors.limit.soft = proc.data.filedescriptors.limit.soft;
                        pt[count].filedescriptors.limit.hard = proc.data.filedescriptors.limit.hard;
                        count++;
                        // Clear
                        memset(&proc.data, 0, sizeof(proc.data));
                        StringBuffer_clear(proc.name);
                }
        }
        StringBuffer_free(&(proc.name));

        *reference = pt;
        globfree(&globbuf);

        return count;
}


/**
 * This routine returns 'nelem' double precision floats containing
 * the load averages in 'loadv'; at most 3 values will be returned.
 * @param loadv destination of the load averages
 * @param nelem number of averages
 * @return: 0 if successful, -1 if failed (and all load averages are 0).
 */
int getloadavg_sysdep(double *loadv, int nelem) {
#ifdef HAVE_GETLOADAVG
        return getloadavg(loadv, nelem);
#else
        char buf[STRLEN];
        double load[3];
        if (! file_readProc(buf, sizeof(buf), "loadavg", -1, NULL))
                return -1;
        if (sscanf(buf, "%lf %lf %lf", &load[0], &load[1], &load[2]) != 3) {
                DEBUG("system statistic error -- cannot get load average\n");
                return -1;
        }
        for (int i = 0; i < nelem; i++)
                loadv[i] = load[i];
        return 0;
#endif
}


/**
 * This routine returns real memory in use.
 * @return: true if successful, false if failed
 */
bool used_system_memory_sysdep(SystemInfo_T *si) {
        char          *ptr;
        char           buf[2048];
        unsigned long  mem_available = 0UL;
        unsigned long  mem_free = 0UL;
        unsigned long  buffers = 0UL;
        unsigned long  cached = 0UL;
        unsigned long  slabreclaimable = 0UL;
        unsigned long  swap_total = 0UL;
        unsigned long  swap_free = 0UL;
        unsigned long long       zfsarcsize = 0ULL;

        if (! file_readProc(buf, sizeof(buf), "meminfo", -1, NULL)) {
                LogError("system statistic error -- cannot get system memory info\n");
                goto error;
        }

        /*
         * Memory
         *
         * First, check if the "MemAvailable" value is available on this system. If it is, we will
         * use it. Otherwise we will attempt to calculate the amount of available memory ourself.
         */
        if ((ptr = strstr(buf, "MemAvailable:")) && sscanf(ptr + 13, "%lu", &mem_available) == 1) {
                si->memory.usage.bytes = systeminfo.memory.size - (unsigned long long)mem_available * 1024;
        } else {
                DEBUG("'MemAvailable' value not available on this system. Attempting to calculate available memory manually...\n");
                if (! (ptr = strstr(buf, "MemFree:")) || sscanf(ptr + 8, "%lu", &mem_free) != 1) {
                        LogError("system statistic error -- cannot get real memory free amount\n");
                        goto error;
                }
                if (! (ptr = strstr(buf, "Buffers:")) || sscanf(ptr + 8, "%lu", &buffers) != 1)
                        DEBUG("system statistic error -- cannot get real memory buffers amount\n");
                if (! (ptr = strstr(buf, "Cached:")) || sscanf(ptr + 7, "%lu", &cached) != 1)
                        DEBUG("system statistic error -- cannot get real memory cache amount\n");
                if (! (ptr = strstr(buf, "SReclaimable:")) || sscanf(ptr + 13, "%lu", &slabreclaimable) != 1)
                        DEBUG("system statistic error -- cannot get slab reclaimable memory amount\n");
                FILE *f = fopen("/proc/spl/kstat/zfs/arcstats", "r");
                if (f) {
                        char line[STRLEN];
                        while (fgets(line, sizeof(line), f)) {
                                if (sscanf(line, "size %*d %llu", &zfsarcsize) == 1) {
                                        break;
                                }
                        }
                        fclose(f);
                }
                si->memory.usage.bytes = systeminfo.memory.size - zfsarcsize - (unsigned long long)(mem_free + buffers + cached + slabreclaimable) * 1024;
        }

        /* Swap */
        if (! (ptr = strstr(buf, "SwapTotal:")) || sscanf(ptr + 10, "%lu", &swap_total) != 1) {
                LogError("system statistic error -- cannot get swap total amount\n");
                goto error;
        }
        if (! (ptr = strstr(buf, "SwapFree:")) || sscanf(ptr + 9, "%lu", &swap_free) != 1) {
                LogError("system statistic error -- cannot get swap free amount\n");
                goto error;
        }
        si->swap.size = (unsigned long long)swap_total * 1024;
        si->swap.usage.bytes = (unsigned long long)(swap_total - swap_free) * 1024;

        return true;

error:
        si->memory.usage.bytes = 0ULL;
        si->swap.size = 0ULL;
        return false;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: true if successful, false if failed (or not available)
 */
bool used_system_cpu_sysdep(SystemInfo_T *si) {
        int rv;
        unsigned long long cpu_total;      // Total CPU time
        unsigned long long cpu_user;       // Time spent in user mode
        unsigned long long cpu_nice;       // Time spent in user mode with low priority (nice)
        unsigned long long cpu_syst;       // Time spent in system mode
        unsigned long long cpu_idle;       // Time idle
        unsigned long long cpu_iowait;     // Time waiting for I/O to complete. This value is not reliable
        unsigned long long cpu_hardirq;    // Time servicing hardware interrupts
        unsigned long long cpu_softirq;    // Time servicing software interrupts
        unsigned long long cpu_steal;      // Stolen time, which is the time spent in other operating systems when running in a virtualized environment
        unsigned long long cpu_guest;      // Time spent running a virtual CPU for guest operating systems under the control of the Linux kernel
        unsigned long long cpu_guest_nice; // Time spent running a niced guest (virtual CPU for guest operating systems under the control of the Linux kernel)
        char buf[8192];

        if (! file_readProc(buf, sizeof(buf), "stat", -1, NULL)) {
                LogError("system statistic error -- cannot read /proc/stat\n");
                goto error;
        }

        rv = sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                    &cpu_user,
                    &cpu_nice,
                    &cpu_syst,
                    &cpu_idle,
                    &cpu_iowait,
                    &cpu_hardirq,
                    &cpu_softirq,
                    &cpu_steal,
                    &cpu_guest,
                    &cpu_guest_nice);
        switch (rv) {
                case 4:
                        // linux < 2.5.41
                        cpu_iowait = 0;
                        cpu_hardirq = 0;
                        cpu_softirq = 0;
                        cpu_steal = 0;
                        cpu_guest = 0;
                        cpu_guest_nice = 0;
                        break;
                case 5:
                        // linux >= 2.5.41
                        cpu_hardirq = 0;
                        cpu_softirq = 0;
                        cpu_steal = 0;
                        cpu_guest = 0;
                        cpu_guest_nice = 0;
                        break;
                case 7:
                        // linux >= 2.6.0-test4
                        cpu_steal = 0;
                        cpu_guest = 0;
                        cpu_guest_nice = 0;
                        break;
                case 8:
                        // linux 2.6.11
                        cpu_guest = 0;
                        cpu_guest_nice = 0;
                        break;
                case 9:
                        // linux >= 2.6.24
                        cpu_guest_nice = 0;
                        break;
                case 10:
                        // linux >= 2.6.33
                        break;
                default:
                        LogError("system statistic error -- cannot read cpu usage\n");
                        goto error;
        }

        cpu_total = cpu_user + cpu_nice + cpu_syst + cpu_idle + cpu_iowait + cpu_hardirq + cpu_softirq + cpu_steal; // Note: cpu_guest and cpu_guest_nice are included in user and nice already

        if (old_cpu_total == 0) {
                si->cpu.usage.user       = -1.;
                si->cpu.usage.nice       = -1.;
                si->cpu.usage.system     = -1.;
                si->cpu.usage.iowait     = -1.;
                si->cpu.usage.hardirq    = -1.;
                si->cpu.usage.softirq    = -1.;
                si->cpu.usage.steal      = -1.;
                si->cpu.usage.guest      = -1.;
                si->cpu.usage.guest_nice = -1.;
        } else {
                double delta = cpu_total - old_cpu_total;
                si->cpu.usage.user       = _usagePercent(old_cpu_user - old_cpu_guest, cpu_user - cpu_guest, delta); // the guest (if available) is sub-statistics of user
                si->cpu.usage.nice       = _usagePercent(old_cpu_nice - old_cpu_guest_nice, cpu_nice - cpu_guest_nice, delta); // the guest_nice (if available) is sub-statistics of nice
                si->cpu.usage.system     = _usagePercent(old_cpu_syst, cpu_syst, delta);
                si->cpu.usage.iowait     = _usagePercent(old_cpu_iowait, cpu_iowait, delta);
                si->cpu.usage.hardirq    = _usagePercent(old_cpu_hardirq, cpu_hardirq, delta);
                si->cpu.usage.softirq    = _usagePercent(old_cpu_softirq, cpu_softirq, delta);
                si->cpu.usage.steal      = _usagePercent(old_cpu_steal, cpu_steal, delta);
                si->cpu.usage.guest      = _usagePercent(old_cpu_guest, cpu_guest, delta);
                si->cpu.usage.guest_nice = _usagePercent(old_cpu_guest_nice, cpu_guest_nice, delta);
        }

        old_cpu_user       = cpu_user;
        old_cpu_nice       = cpu_nice;
        old_cpu_syst       = cpu_syst;
        old_cpu_iowait     = cpu_iowait;
        old_cpu_hardirq    = cpu_hardirq;
        old_cpu_softirq    = cpu_softirq;
        old_cpu_steal      = cpu_steal;
        old_cpu_guest      = cpu_guest;
        old_cpu_guest_nice = cpu_guest_nice;
        old_cpu_total      = cpu_total;
        return true;

error:
        si->cpu.usage.user       = 0.;
        si->cpu.usage.nice       = 0.;
        si->cpu.usage.system     = 0.;
        si->cpu.usage.iowait     = 0.;
        si->cpu.usage.hardirq    = 0.;
        si->cpu.usage.softirq    = 0.;
        si->cpu.usage.steal      = 0.;
        si->cpu.usage.guest      = 0.;
        si->cpu.usage.guest_nice = 0.;
        return false;
}


/**
 * This routine returns filedescriptors statistics
 * @return: true if successful, false if failed (or not available)
 */
bool used_system_filedescriptors_sysdep(SystemInfo_T *si) {
        bool rv = false;
        FILE *f = fopen("/proc/sys/fs/file-nr", "r");
        if (f) {
                char line[STRLEN];
                if (fgets(line, sizeof(line), f)) {
                        if (sscanf(line, "%lld %lld %lld\n", &(si->filedescriptors.allocated), &(si->filedescriptors.unused), &(si->filedescriptors.maximum)) == 3) {
                                rv = true;
                        }
                }
                fclose(f);
        } else {
                DEBUG("system statistic error -- cannot open /proc/sys/fs/file-nr\n");
        }
        return rv;
}


bool available_statistics(SystemInfo_T *si) {
        int rv;
        unsigned long long cpu_user;       // Time spent in user mode
        unsigned long long cpu_nice;       // Time spent in user mode with low priority (nice)
        unsigned long long cpu_syst;       // Time spent in system mode
        unsigned long long cpu_idle;       // Time idle
        unsigned long long cpu_iowait;     // Time waiting for I/O to complete. This value is not reliable
        unsigned long long cpu_hardirq;    // Time servicing hardware interrupts
        unsigned long long cpu_softirq;    // Time servicing software interrupts
        unsigned long long cpu_steal;      // Stolen time, which is the time spent in other operating systems when running in a virtualized environment
        unsigned long long cpu_guest;      // Time spent running a virtual CPU for guest operating systems under the control of the Linux kernel
        unsigned long long cpu_guest_nice; // Time spent running a niced guest (virtual CPU for guest operating systems under the control of the Linux kernel)
        char buf[8192];

        if (! file_readProc(buf, sizeof(buf), "stat", -1, NULL)) {
                LogError("system statistic error -- cannot read /proc/stat\n");
                return false;
        }

        rv = sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
                    &cpu_user,
                    &cpu_nice,
                    &cpu_syst,
                    &cpu_idle,
                    &cpu_iowait,
                    &cpu_hardirq,
                    &cpu_softirq,
                    &cpu_steal,
                    &cpu_guest,
                    &cpu_guest_nice);
        switch (rv) {
                case 4:
                        // linux < 2.5.41
                        si->statisticsAvailable |= Statistics_CpuUser | Statistics_CpuNice | Statistics_CpuSystem;
                        break;
                case 5:
                        // linux >= 2.5.41
                        si->statisticsAvailable |= Statistics_CpuUser | Statistics_CpuNice | Statistics_CpuSystem | Statistics_CpuIOWait;
                        break;
                case 7:
                        // linux >= 2.6.0-test4
                        si->statisticsAvailable |= Statistics_CpuUser | Statistics_CpuNice | Statistics_CpuSystem | Statistics_CpuIOWait | Statistics_CpuHardIRQ | Statistics_CpuSoftIRQ;
                        break;
                case 8:
                        // linux 2.6.11
                        si->statisticsAvailable |= Statistics_CpuUser | Statistics_CpuNice | Statistics_CpuSystem | Statistics_CpuIOWait | Statistics_CpuHardIRQ | Statistics_CpuSoftIRQ | Statistics_CpuSteal;
                        break;
                case 9:
                        // linux >= 2.6.24
                        si->statisticsAvailable |= Statistics_CpuUser | Statistics_CpuNice | Statistics_CpuSystem | Statistics_CpuIOWait | Statistics_CpuHardIRQ | Statistics_CpuSoftIRQ | Statistics_CpuSteal | Statistics_CpuGuest;
                        break;
                case 10:
                        // linux >= 2.6.33
                        si->statisticsAvailable |= Statistics_CpuUser | Statistics_CpuNice | Statistics_CpuSystem | Statistics_CpuIOWait | Statistics_CpuHardIRQ | Statistics_CpuSoftIRQ | Statistics_CpuSteal | Statistics_CpuGuest | Statistics_CpuGuestNice;
                        break;
                default:
                        LogError("system statistic error -- cannot read cpu usage\n");
                        return false;
        }

        si->statisticsAvailable |= Statistics_FiledescriptorsPerSystem | Statistics_FiledescriptorsPerProcess;

#ifdef HAVE_PRLIMIT
        si->statisticsAvailable |= Statistics_FiledescriptorsPerProcessMax;
#endif

        return true;
}

