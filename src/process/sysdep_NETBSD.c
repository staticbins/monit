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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_PROC_H
#include <sys/proc.h>
#endif

#ifdef HAVE_KVM_H
#include <kvm.h>
#endif

#ifdef HAVE_UVM_UVM_H
#include <uvm/uvm.h>
#endif

#ifdef HAVE_UVM_UVM_EXTERN_H
#include <uvm/uvm_extern.h>
#endif

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_SYS_DKSTAT_H
#include <sys/dkstat.h>
#endif

#include "monit.h"
#include "ProcessTree.h"
#include "process_sysdep.h"

// libmonit
#include "system/Time.h"

/**
 *  System dependent resource data collecting code for NetBSD.
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


static int      pagesize;
static long     total_old    = 0;
static long     cpu_user_old = 0;
static long     cpu_nice_old = 0;
static long     cpu_syst_old = 0;
static long     cpu_intr_old = 0;
static unsigned int maxslp;


/* ------------------------------------------------------------------ Public */


bool init_systeminfo_sysdep(void) {
        int mib[2] = {CTL_HW, HW_NCPU};
        size_t len = sizeof(System_Info.cpu.count);
        if (sysctl(mib, 2, &System_Info.cpu.count, &len, NULL, 0) == -1) {
                DEBUG("system statistic error -- cannot get cpu count: %s\n", STRERROR);
                return false;
        }

        mib[1] = HW_PHYSMEM;
        len    = sizeof(System_Info.memory.size);
        if (sysctl(mib, 2, &System_Info.memory.size, &len, NULL, 0) == -1) {
                DEBUG("system statistic error -- cannot get real memory amount: %s\n", STRERROR);
                return false;
        }

        mib[1] = HW_PAGESIZE;
        len    = sizeof(pagesize);
        if (sysctl(mib, 2, &pagesize, &len, NULL, 0) == -1) {
                DEBUG("system statistic error -- cannot get memory page size: %s\n", STRERROR);
                return false;
        }

        struct timeval booted;
        mib[0] = CTL_KERN;
        mib[1] = KERN_BOOTTIME;
        len = sizeof(booted);
        if (sysctl(mib, 2, &booted, &len, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl kern.boottime failed: %s\n", STRERROR);
                return false;
        } else {
                System_Info.booted = booted.tv_sec;
        }

        return true;
}


/**
 * Read all processes to initialize the information tree.
 * @param reference reference of ProcessTree
 * @param pflags Process engine flags
 * @return treesize > 0 if succeeded otherwise 0
 */
int init_processtree_sysdep(ProcessTree_T **reference, ProcessEngine_Flags pflags) {
        size_t size = sizeof(maxslp);
        static int mib_maxslp[] = {CTL_VM, VM_MAXSLP};
        if (sysctl(mib_maxslp, 2, &maxslp, &size, NULL, 0) < 0) {
                Log_error("system statistic error -- vm.maxslp failed\n");
                return 0;
        }

        int mib_proc2[6] = {CTL_KERN, KERN_PROC2, KERN_PROC_ALL, 0, sizeof(struct kinfo_proc2), 0};
        if (sysctl(mib_proc2, 6, NULL, &size, NULL, 0) == -1) {
                Log_error("system statistic error -- kern.proc2 #1 failed\n");
                return 0;
        }

        size *= 2; // Add reserve for new processes which were created between calls of sysctl
        struct kinfo_proc2 *pinfo = CALLOC(1, size);
        mib_proc2[5] = (int)(size / sizeof(struct kinfo_proc2));
        if (sysctl(mib_proc2, 6, pinfo, &size, NULL, 0) == -1) {
                FREE(pinfo);
                Log_error("system statistic error -- kern.proc2 #2 failed\n");
                return 0;
        }

        int treesize = (int)(size / sizeof(struct kinfo_proc2));

        ProcessTree_T *pt = CALLOC(sizeof(ProcessTree_T), treesize);

        char buf[_POSIX2_LINE_MAX];
        kvm_t *kvm_handle = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, buf);
        if (! kvm_handle) {
                FREE(pinfo);
                FREE(pt);
                Log_error("system statistic error -- kvm_openfiles failed: %s\n", buf);
                return 0;
        }

        unsigned long long now = Time_milli();
        StringBuffer_T cmdline = NULL;
        if (pflags & ProcessEngine_CollectCommandLine)
                cmdline = StringBuffer_create(64);
        for (int i = 0; i < treesize; i++) {
                pt[i].pid                 = pinfo[i].p_pid;
                pt[i].ppid                = pinfo[i].p_ppid;
                pt[i].cred.uid            = pinfo[i].p_ruid;
                pt[i].cred.euid           = pinfo[i].p_uid;
                pt[i].cred.gid            = pinfo[i].p_rgid;
                pt[i].threads.self        = pinfo[i].p_nlwps;
                pt[i].uptime              = System_Info.time / 10. - pinfo[i].p_ustart_sec;
                pt[i].cpu.time            = pinfo[i].p_rtime_sec * 10 + (double)pinfo[i].p_rtime_usec / 100000.;
                pt[i].memory.usage        = (unsigned long long)pinfo[i].p_vm_rssize * (unsigned long long)pagesize;
                pt[i].zombie              = pinfo[i].p_stat == SZOMB ? true : false;
                pt[i].read.bytes          = -1;
                pt[i].read.bytesPhysical  = -1;
                pt[i].read.operations     = pinfo[i].p_uru_inblock;
                pt[i].read.time           = now;
                pt[i].write.bytes         = -1;
                pt[i].write.bytesPhysical = -1;
                pt[i].write.operations    = pinfo[i].p_uru_oublock;
                pt[i].write.time          = now;
                if (pflags & ProcessEngine_CollectCommandLine) {
                        char **args = kvm_getargv2(kvm_handle, &pinfo[i], 0);
                        if (args) {
                                StringBuffer_clear(cmdline);
                                for (int j = 0; args[j]; j++)
                                        StringBuffer_append(cmdline, args[j + 1] ? "%s " : "%s", args[j]);
                                if (StringBuffer_length(cmdline))
                                        pt[i].cmdline = Str_dup(StringBuffer_toString(StringBuffer_trim(cmdline)));
                        }
                        if (STR_UNDEF(pt[i].cmdline)) {
                                FREE(pt[i].cmdline);
                                pt[i].cmdline = Str_dup(pinfo[i].p_comm);
                        }
                }
        }
        if (pflags & ProcessEngine_CollectCommandLine)
                StringBuffer_free(&cmdline);
        FREE(pinfo);
        kvm_close(kvm_handle);

        *reference = pt;

        return treesize;
}


/**
 * This routine returns 'nelem' double precision floats containing
 * the load averages in 'loadv'; at most 3 values will be returned.
 * @param loadv destination of the load averages
 * @param nelem number of averages
 * @return: 0 if successful, -1 if failed (and all load averages are 0).
 */
int getloadavg_sysdep (double *loadv, int nelem) {
        return getloadavg(loadv, nelem);
}


/**
 * This routine returns kbyte of real memory in use.
 * @return: true if successful, false if failed (or not available)
 */
bool used_system_memory_sysdep(SystemInfo_T *si) {
        struct uvmexp_sysctl vm;
        int mib[2] = {CTL_VM, VM_UVMEXP2};
        size_t len = sizeof(struct uvmexp_sysctl);
        if (sysctl(mib, 2, &vm, &len, NULL, 0) == -1) {
                Log_error("system statistic error -- cannot get memory usage: %s\n", STRERROR);
                si->swap.size = 0ULL;
                return false;
        }
        si->memory.usage.bytes = (unsigned long long)(vm.active + vm.wired) * (unsigned long long)vm.pagesize;
        si->swap.size = (unsigned long long)vm.swpages * (unsigned long long)vm.pagesize;
        si->swap.usage.bytes = (unsigned long long)vm.swpginuse * (unsigned long long)vm.pagesize;
        return true;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: true if successful, false if failed
 */
bool used_system_cpu_sysdep(SystemInfo_T *si) {
        int       mib[] = {CTL_KERN, KERN_CP_TIME};
        long long cp_time[CPUSTATES];
        long      total_new = 0;
        long      total;
        size_t    len;

        len = sizeof(cp_time);
        if (sysctl(mib, 2, &cp_time, &len, NULL, 0) == -1) {
                Log_error("system statistic error -- cannot get cpu time: %s\n", STRERROR);
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


bool used_system_filedescriptors_sysdep(__attribute__ ((unused)) SystemInfo_T *si) {
        // Not implemented
        return true;
}


bool available_statistics(SystemInfo_T *si) {
        si->statisticsAvailable = Statistics_CpuUser | Statistics_CpuSystem | Statistics_CpuNice | Statistics_CpuHardIRQ;
        return true;
}


pid_t Sysdep_getMainThread(pid_t pid) {
        return pid;
}

