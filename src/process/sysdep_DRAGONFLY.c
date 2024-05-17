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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_KINFO_H
#include <kinfo.h>
#endif

#ifdef HAVE_KVM_H
#include <kvm.h>
#endif

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_PROC_H
#include <sys/proc.h>
#endif

#ifdef HAVE_SYS_USER_H
#include <sys/user.h>
#endif

#ifdef HAVE_SYS_VMMETER_H
#include <sys/vmmeter.h>
#endif

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_SYS_DKSTAT_H
#include <sys/dkstat.h>
#endif

#include "monit.h"
#include "ProcessTable.h"
#include "process_sysdep.h"


/**
 *  System dependent resource gathering code for DragonFly.
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


static int  pagesize;
static long total_old    = 0;
static long cpu_user_old = 0;
static long cpu_nice_old = 0;
static long cpu_syst_old = 0;
static long cpu_intr_old = 0;


/* ------------------------------------------------------------------ Public */


bool init_systeminfo_sysdep(void) {
        int mib[2] = {CTL_HW, HW_NCPU};
        size_t len = sizeof(System_Info.cpu.count);
        if (sysctl(mib, 2, &System_Info.cpu.count, &len, NULL, 0) == -1) {
                DEBUG("system statistic error -- cannot get cpu count: %s\n", System_lastError());
                return false;
        }

        mib[1] = HW_PHYSMEM;
        len    = sizeof(System_Info.memory.size);
        if (sysctl(mib, 2, &System_Info.memory.size, &len, NULL, 0) == -1) {
                DEBUG("system statistic error -- cannot get real memory amount: %s\n", System_lastError());
                return false;
        }

        mib[1] = HW_PAGESIZE;
        len    = sizeof(pagesize);
        if (sysctl(mib, 2, &pagesize, &len, NULL, 0) == -1) {
                DEBUG("system statistic error -- cannot get memory page size: %s\n", System_lastError());
                return false;
        }

        struct timeval booted;
        size_t size = sizeof(booted);
        if (sysctlbyname("kern.boottime", &booted, &size, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl kern.boottime failed: %s\n", System_lastError());
                return false;
        } else {
                System_Info.booted = booted.tv_sec;
        }

        return true;
}


/**
 * Read all processes to initialize the information tree.
 * @param reference  a process_t reference
 * @param pflags Process engine flags
 * @return treesize > 0 if succeeded otherwise 0.
 */
int init_processtree_sysdep(process_t *reference, ProcessEngine_Flags pflags) {
        kvm_t *kvm_handle = kvm_open(NULL, _PATH_DEVNULL, NULL, O_RDONLY, prog);
        if (! kvm_handle) {
                Log_error("system statistic error -- cannot initialize kvm interface\n");
                return 0;
        }

        int treesize;
        struct kinfo_proc *pinfo = kvm_getprocs(kvm_handle, KERN_PROC_ALL, 0, &treesize);
        if (! pinfo || (treesize < 1)) {
                Log_error("system statistic error -- cannot get process tree\n");
                kvm_close(kvm_handle);
                return 0;
        }

        process_t pt = CALLOC(sizeof(struct process_t), treesize);

        unsigned long long now = Time_milli();
        StringBuffer_T cmdline = NULL;
        if (pflags & ProcessEngine_CollectCommandLine)
                cmdline = StringBuffer_create(64);
        for (int i = 0; i < treesize; i++) {
                pt[i].pid                 = pinfo[i].kp_pid;
                pt[i].ppid                = pinfo[i].kp_ppid;
                pt[i].cred.uid            = pinfo[i].kp_ruid;
                pt[i].cred.euid           = pinfo[i].kp_uid;
                pt[i].cred.gid            = pinfo[i].kp_rgid;
                pt[i].threads.self        = pinfo[i].kp_nthreads;
                pt[i].uptime              = System_Info.time / 10. - pinfo[i].kp_start.tv_sec;
                pt[i].cpu.time            = (double)((pinfo[i].kp_lwp.kl_uticks + pinfo[i].kp_lwp.kl_sticks + pinfo[i].kp_lwp.kl_iticks) / 1000000.);
                pt[i].memory.usage        = (unsigned long long)pinfo[i].kp_vm_rssize * (unsigned long long)pagesize;
                pt[i].read.bytes          = -1;
                pt[i].read.bytesPhysical  = -1;
                pt[i].read.operations     = pinfo[i].kp_ru.ru_inblock;
                pt[i].read.time           = now;
                pt[i].write.bytes         = -1;
                pt[i].write.bytesPhysical = -1;
                pt[i].write.operations    = pinfo[i].kp_ru.ru_oublock;
                pt[i].write.time          = now;
                pt[i].zombie              = pinfo[i].kp_stat == SZOMB ? true : false;
                if (pflags & ProcessEngine_CollectCommandLine) {
                        char **args = kvm_getargv(kvm_handle, &pinfo[i], 0);
                        if (args) {
                                StringBuffer_clear(cmdline);
                                for (int j = 0; args[j]; j++)
                                        StringBuffer_append(cmdline, args[j + 1] ? "%s " : "%s", args[j]);
                                if (StringBuffer_length(cmdline))
                                        pt[i].cmdline = Str_dup(StringBuffer_toString(StringBuffer_trim(cmdline)));
                        }
                        if (STR_UNDEF(pt[i].cmdline)) {
                                FREE(pt[i].cmdline);
                                pt[i].cmdline = Str_dup(pinfo[i].kp_comm);
                        }
                }
        }
        if (pflags & ProcessEngine_CollectCommandLine)
                StringBuffer_free(&cmdline);

        *reference = pt;
        kvm_close(kvm_handle);

        return treesize;
}


/**
 * This routine returns 'nelem' double precision floats containing
 * the load averages in 'loadv'; at most 3 values will be returned.
 * @param loadv destination of the load averages
 * @param nelem number of averages
 * @return: 0 if successful, -1 if failed (and all load averages are 0).
 */
int getloadavg_sysdep(double *loadv, int nelem) {
        return getloadavg(loadv, nelem);
}


/**
 * This routine returns kbyte of real memory in use.
 * @return: true if successful, false if failed (or not available)
 */
bool used_system_memory_sysdep(SystemInfo_T *si) {
        /* Memory */
        size_t len = sizeof(unsigned int);
        unsigned int active;
        if (sysctlbyname("vm.stats.vm.v_active_count", &active, &len, NULL, 0) == -1) {
                Log_error("system statistic error -- cannot get for active memory usage: %s\n", System_lastError());
                return false;
        }
        if (len != sizeof(unsigned int)) {
                Log_error("system statistic error -- active memory usage statics error\n");
                return false;
        }
        unsigned int wired;
        if (sysctlbyname("vm.stats.vm.v_wire_count", &wired, &len, NULL, 0) == -1) {
                Log_error("system statistic error -- cannot get for wired memory usage: %s\n", System_lastError());
                return false;
        }
        if (len != sizeof(unsigned int)) {
                Log_error("system statistic error -- wired memory usage statics error\n");
                return false;
        }
        si->memory.usage.bytes = (unsigned long long)(active + wired) * (unsigned long long)pagesize;

        /* Swap */
        unsigned int used;
        if (sysctlbyname("vm.swap_anon_use", &used, &len, NULL, 0) == -1) {
                Log_error("system statistic error -- cannot get swap usage: %s\n", System_lastError());
                si->swap.size = 0;
                return false;
        }
        si->swap.usage.bytes = (unsigned long long)used * (unsigned long long)pagesize;
        if (sysctlbyname("vm.swap_cache_use", &used, &len, NULL, 0) == -1) {
                Log_error("system statistic error -- cannot get swap usage: %s\n", System_lastError());
                si->swap.size = 0;
                return false;
        }
        si->swap.usage.bytes += (unsigned long long)used * (unsigned long long)pagesize;
        unsigned int free;
        if (sysctlbyname("vm.swap_size", &free, &len, NULL, 0) == -1) {
                Log_error("system statistic error -- cannot get swap usage: %s\n", System_lastError());
                si->swap.size = 0;
                return false;
        }
        si->swap.size = (unsigned long long)free * (unsigned long long)pagesize + si->swap.usage.bytes;
        return true;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: true if successful, false if failed
 */
bool used_system_cpu_sysdep(SystemInfo_T *si) {
        int    mib[2];
        long   cp_time[CPUSTATES];
        long   total_new = 0;
        long   total;
        size_t len;

        len = sizeof(mib);
        if (sysctlnametomib("kern.cp_time", mib, &len) == -1) {
                Log_error("system statistic error -- cannot get cpu time handler: %s\n", System_lastError());
                return false;
        }

        len = sizeof(cp_time);
        if (sysctl(mib, 2, &cp_time, &len, NULL, 0) == -1) {
                Log_error("system statistic error -- cannot get cpu time: %s\n", System_lastError());
                return false;
        }

        for (int i = 0; i < CPUSTATES; i++)
                total_new += cp_time[i];

        total     = total_new - total_old;
        total_old = total_new;

        si->cpu.usage.user = (total > 0) ? (100. * (double)(cp_time[CP_USER] - cpu_user_old) / total) : -1.;
        si->cpu.usage.nice = (total > 0) ? (100. * (double)(cp_time[CP_NICE] - cpu_nice_old) / total) : -1.;
        si->cpu.usage.system = (total > 0) ? (100. * (double)(cp_time[CP_SYS] - cpu_syst_old) / total) : -1.;
        si->cpu.usage.hardirq = (total > 0) ? (100. * (double)(cp_time[CP_INTR] - cpu_intr_old) / total) : -1.;

        cpu_user_old = cp_time[CP_USER];
        cpu_nice_old = cp_time[CP_NICE];
        cpu_syst_old = cp_time[CP_SYS];
        cpu_intr_old = cp_time[CP_INTR];

        return true;
}


bool used_system_filedescriptors_sysdep(SystemInfo_T *si) {
        // Open files
        size_t len = sizeof(si->filedescriptors.allocated);
        if (sysctlbyname("kern.openfiles", &si->filedescriptors.allocated, &len, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl kern.openfiles failed: %s\n", System_lastError());
                return false;
        }
        // Max files
        int mib[2] = {CTL_KERN, KERN_MAXFILES};
        len = sizeof(si->filedescriptors.maximum);
        if (sysctl(mib, 2, &si->filedescriptors.maximum, &len, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl kern.maxfiles failed: %s\n", System_lastError());
                return false;
        }
        return true;
}


bool available_statistics(SystemInfo_T *si) {
        si->statisticsAvailable = Statistics_CpuUser | Statistics_CpuSystem | Statistics_CpuNice | Statistics_CpuHardIRQ | Statistics_FiledescriptorsPerSystem;
        return true;
}

