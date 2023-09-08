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

#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#ifdef HAVE_MACH_MACH_H
#include <mach/mach.h>
#endif

#ifdef HAVE_LIBPROC_H
#include <libproc.h>
#endif

#ifdef HAVE_COREFOUNDATION_COREFOUNDATION_H
#include <CoreFoundation/CoreFoundation.h>
#endif

#include "monit.h"
#include "ProcessTable.h"
#include "process_sysdep.h"

// libmonit
#include "system/Time.h"


/**
 *  System dependent resource data collecting code for MacOS X.
 *
 *  @file
 */


#define ARGSSIZE 8192


/* ----------------------------------------------------------------- Private */


static int  pagesize;
static long total_old    = 0;
static long cpu_user_old = 0;
static long cpu_nice_old = 0;
static long cpu_syst_old = 0;


void static _setOSInfo(void) {
#ifdef HAVE_COREFOUNDATION_COREFOUNDATION_H
        CFURLRef url = CFURLCreateWithFileSystemPath(NULL, CFSTR("/System/Library/CoreServices/SystemVersion.plist"), kCFURLPOSIXPathStyle, false);
        if (url) {
                CFReadStreamRef stream = CFReadStreamCreateWithFile(NULL, url);
                if (stream) {
                        if (CFReadStreamOpen(stream)) {
                                CFPropertyListRef propertyList = CFPropertyListCreateWithStream(NULL, stream, 0, kCFPropertyListImmutable, NULL, NULL);
                                if (propertyList) {
                                        CFStringRef value = CFDictionaryGetValue(propertyList, CFSTR("ProductName"));
                                        if (value) {
                                                CFStringGetCString(value, System_Info.uname.sysname, sizeof(System_Info.uname.sysname), CFStringGetSystemEncoding());
                                        }
                                        value = CFDictionaryGetValue(propertyList, CFSTR("ProductVersion"));
                                        if (value) {
                                                CFStringGetCString(value, System_Info.uname.release, sizeof(System_Info.uname.release), CFStringGetSystemEncoding());
                                        }
                                        CFRelease(propertyList);
                                }
                                CFReadStreamClose(stream);
                        }
                        CFRelease(stream);
                }
                CFRelease(url);
        }
#endif
}


extern int responsibility_get_pid_responsible_for_pid(pid_t);
static pid_t _responsible(pid_t p, pid_t pp) {
        pid_t r = responsibility_get_pid_responsible_for_pid(p);
        if (r < 0)
                return pp;
        return (r == p) ? pp : r;
}


/* ------------------------------------------------------------------ Public */


bool init_systeminfo_sysdep(void) {
        _setOSInfo();
        size_t size = sizeof(System_Info.cpu.count);
        if (sysctlbyname("hw.logicalcpu", &System_Info.cpu.count, &size, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl hw.logicalcpu failed: %s\n", STRERROR);
                return false;
        }
        size = sizeof(System_Info.memory.size);
        if (sysctlbyname("hw.memsize", &System_Info.memory.size, &size, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl hw.memsize failed: %s\n", STRERROR);
                return false;
        }
        size = sizeof(pagesize);
        if (sysctlbyname("hw.pagesize", &pagesize, &size, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl hw.pagesize failed: %s\n", STRERROR);
                return false;
        }
        size = sizeof(System_Info.argmax);
        if (sysctlbyname("kern.argmax", &System_Info.argmax, &size, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl kern.argmax failed: %s\n", STRERROR);
                return false;
        }
        struct timeval booted;
        size = sizeof(booted);
        if (sysctlbyname("kern.boottime", &booted, &size, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl kern.boottime failed: %s\n", STRERROR);
                return false;
        } else {
                System_Info.booted = booted.tv_sec;
        }
        return true;
}


/**
 * Read all processes to initialize the information tree.
 * @param reference a process_t reference 
 * @param pflags Process engine flags
 * @return treesize > 0 if succeeded otherwise 0
 */
int init_processtree_sysdep(process_t *reference, ProcessEngine_Flags pflags) {
        size_t pinfo_size = 0;
        int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
        if (sysctl(mib, 4, NULL, &pinfo_size, NULL, 0) < 0) {
                Log_error("system statistic error -- sysctl failed: %s\n", STRERROR);
                return 0;
        }
        struct kinfo_proc *pinfo = CALLOC(1, pinfo_size);
        if (sysctl(mib, 4, pinfo, &pinfo_size, NULL, 0)) {
                FREE(pinfo);
                Log_error("system statistic error -- sysctl failed: %s\n", STRERROR);
                return 0;
        }
        size_t treesize = pinfo_size / sizeof(struct kinfo_proc);
        process_t pt = CALLOC(sizeof(struct process_t), treesize);
        char *args = NULL;
        StringBuffer_T cmdline = NULL;
        if (pflags & ProcessEngine_CollectCommandLine) {
                cmdline = StringBuffer_create(64);
                args = CALLOC(1, System_Info.argmax + 1);
        }
        for (size_t i = 0; i < treesize; i++) {
                pt[i].uptime    = System_Info.time / 10. - pinfo[i].kp_proc.p_starttime.tv_sec;
                pt[i].zombie    = pinfo[i].kp_proc.p_stat == SZOMB ? true : false;
                pt[i].pid       = pinfo[i].kp_proc.p_pid;
                pt[i].ppid      = pinfo[i].kp_eproc.e_ppid;
                pt[i].cred.uid  = pinfo[i].kp_eproc.e_pcred.p_ruid;
                pt[i].cred.euid = pinfo[i].kp_eproc.e_ucred.cr_uid;
                pt[i].cred.gid  = pinfo[i].kp_eproc.e_pcred.p_rgid;
                if (pflags & ProcessEngine_CollectCommandLine) {
                        size_t size = System_Info.argmax;
                        mib[0] = CTL_KERN;
                        mib[1] = KERN_PROCARGS2;
                        mib[2] = pt[i].pid;
                        if (sysctl(mib, 3, args, &size, NULL, 0) != -1) {
                                /* KERN_PROCARGS2 sysctl() returns following pseudo structure:
                                 *        struct {
                                 *                int argc
                                 *                char execname[];
                                 *                char argv[argc][];
                                 *                char env[][];
                                 *        }
                                 * The strings are terminated with '\0' and may have variable '\0' padding
                                 */
                                int argc = *args;
                                char *p = args + sizeof(int); // arguments beginning
                                StringBuffer_clear(cmdline);
                                p += strlen(p); // skip exename
                                while (argc > 0 && p < args + System_Info.argmax) {
                                        if (*p == 0) { // skip terminating 0 and variable length 0 padding
                                                p++;
                                                continue;
                                        }
                                        StringBuffer_append(cmdline, argc-- ? "%s " : "%s", p);
                                        p += strlen(p);
                                }
                                if (StringBuffer_length(cmdline))
                                        pt[i].cmdline = Str_dup(StringBuffer_toString(StringBuffer_trim(cmdline)));
                        }
                        if (STR_UNDEF(pt[i].cmdline)) {
                                char cmdpath[PROC_PIDPATHINFO_MAXSIZE] = {};
                                FREE(pt[i].cmdline);
                                if (proc_pidpath(pt[i].pid, cmdpath, sizeof(cmdpath)) > 0) {
                                        pt[i].cmdline = Str_dup(cmdpath);
                                } else {
                                        pt[i].cmdline = Str_dup(pinfo[i].kp_proc.p_comm);
                                }
                        }
                }
                if (! pt[i].zombie) {
                        // CPU, memory, threads
                        struct proc_taskinfo tinfo;
                        int rv = proc_pidinfo(pt[i].pid, PROC_PIDTASKINFO, 0, &tinfo, sizeof(tinfo)); // If the process is zombie, skip this
                        if (rv <= 0) {
                                if (errno != EPERM)
                                        DEBUG("proc_pidinfo for pid %d failed -- %s\n", pt[i].pid, STRERROR);
                        } else if ((unsigned long)rv < sizeof(tinfo)) {
                                Log_error("proc_pidinfo for pid %d -- invalid result size\n", pt[i].pid);
                        } else {
                                pt[i].memory.usage = (unsigned long long)tinfo.pti_resident_size;
                                pt[i].cpu.time = (double)(tinfo.pti_total_user + tinfo.pti_total_system) / 100000000.; // The time is in nanoseconds, we store it as ms
                                pt[i].threads.self = tinfo.pti_threadnum;
                        }
                        // Disk IO
                        rusage_info_current rusage;
                        if (proc_pid_rusage(pt[i].pid, RUSAGE_INFO_CURRENT, (rusage_info_t *)&rusage) < 0) {
                                if (errno != EPERM)
                                        DEBUG("proc_pid_rusage for pid %d failed -- %s\n", pt[i].pid, STRERROR);
                        } else {
                                pt[i].read.time = pt[i].write.time = Time_milli();
                                pt[i].read.bytes = -1;
                                pt[i].read.bytesPhysical = rusage.ri_diskio_bytesread;
                                pt[i].read.operations = -1;
                                pt[i].write.bytes = -1;
                                pt[i].write.bytesPhysical = rusage.ri_diskio_byteswritten;
                                pt[i].write.operations = -1;
                        }
                }
                if (pt[i].ppid == 1) {
                        pt[i].ppid = _responsible(pt[i].pid, pt[i].ppid);
                }
                
        }
        if (pflags & ProcessEngine_CollectCommandLine) {
                StringBuffer_free(&cmdline);
                FREE(args);
        }
        FREE(pinfo);
        
        *reference = pt;
        
        return (int)treesize;
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
 * This routine returns real memory in use.
 * @return: true if successful, false if failed (or not available)
 */
bool used_system_memory_sysdep(SystemInfo_T *si) {
        /* Memory */
        vm_statistics_data_t page_info;
        mach_msg_type_number_t count = HOST_VM_INFO_COUNT;
        kern_return_t kret = host_statistics(mach_host_self(), HOST_VM_INFO, (host_info_t)&page_info, &count);
        if (kret != KERN_SUCCESS) {
                DEBUG("system statistic error -- cannot get memory usage\n");
                return false;
        }
        si->memory.usage.bytes = (unsigned long long)(page_info.wire_count + page_info.active_count) * (unsigned long long)pagesize;
        
        /* Swap */
        int mib[2] = {CTL_VM, VM_SWAPUSAGE};
        size_t len = sizeof(struct xsw_usage);
        struct xsw_usage swap;
        if (sysctl(mib, 2, &swap, &len, NULL, 0) == -1) {
                DEBUG("system statistic error -- cannot get swap usage: %s\n", STRERROR);
                si->swap.size = 0ULL;
                return false;
        }
        si->swap.size = (unsigned long long)swap.xsu_total;
        si->swap.usage.bytes = (unsigned long long)swap.xsu_used;
        
        return true;
}


/**
 * This routine returns system/user CPU time in use.
 * @return: true if successful, false if failed
 */
bool used_system_cpu_sysdep(SystemInfo_T *si) {
        long                      total;
        long                      total_new = 0;
        kern_return_t             kret;
        host_cpu_load_info_data_t cpu_info;
        mach_msg_type_number_t    count;
        
        count = HOST_CPU_LOAD_INFO_COUNT;
        kret  = host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t)&cpu_info, &count);
        if (kret == KERN_SUCCESS) {
                for (int i = 0; i < CPU_STATE_MAX; i++)
                        total_new += cpu_info.cpu_ticks[i];
                total     = total_new - total_old;
                total_old = total_new;
                
                si->cpu.usage.user = (total > 0) ? (100. * (double)(cpu_info.cpu_ticks[CPU_STATE_USER] - cpu_user_old) / total) : -1.;
                si->cpu.usage.nice = (total > 0) ? (100. * (double)(cpu_info.cpu_ticks[CPU_STATE_NICE] - cpu_nice_old) / total) : -1.;
                si->cpu.usage.system = (total > 0) ? (100. * (double)(cpu_info.cpu_ticks[CPU_STATE_SYSTEM] - cpu_syst_old) / total) : -1.;
                
                cpu_user_old = cpu_info.cpu_ticks[CPU_STATE_USER];
                cpu_nice_old = cpu_info.cpu_ticks[CPU_STATE_NICE];
                cpu_syst_old = cpu_info.cpu_ticks[CPU_STATE_SYSTEM];
                
                return true;
        }
        return false;
}


bool used_system_filedescriptors_sysdep(__attribute__ ((unused)) SystemInfo_T *si) {
        // Open files
        size_t len = sizeof(si->filedescriptors.allocated);
        if (sysctlbyname("kern.num_files", &si->filedescriptors.allocated, &len, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl kern.openfiles failed: %s\n", STRERROR);
                return false;
        }
        // Max files
        int mib[2] = {CTL_KERN, KERN_MAXFILES};
        len = sizeof(si->filedescriptors.maximum);
        if (sysctl(mib, 2, &si->filedescriptors.maximum, &len, NULL, 0) == -1) {
                DEBUG("system statistics error -- sysctl kern.maxfiles failed: %s\n", STRERROR);
                return false;
        }
        return true;
}


bool available_statistics(SystemInfo_T *si) {
        si->statisticsAvailable = Statistics_CpuUser | Statistics_CpuSystem | Statistics_CpuNice | Statistics_FiledescriptorsPerSystem;
        return true;
}

