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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
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

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "monit.h"
#include "event.h"
#include "ProcessTree.h"
#include "process_sysdep.h"
#include "TextBox.h"
#include "TextColor.h"

// libmonit
#include "system/Time.h"


/**
 *  General purpose /proc methods.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


static int ptreesize = 0;
static ProcessTree_T *ptree = NULL;


/* ----------------------------------------------------------------- Private */


static void _delete(ProcessTree_T **pt, int *size) {
        ASSERT(pt);
        ProcessTree_T *_pt = *pt;
        if (_pt) {
                for (int i = 0; i < *size; i++) {
                        FREE(_pt[i].cmdline);
                        FREE(_pt[i].children.list);
                        FREE(_pt[i].secattr);
                }
                FREE(_pt);
                *pt = NULL;
                *size = 0;
        }
}


/**
 * Search a leaf in the processtree
 * @param pid  pid of the process
 * @param pt  processtree
 * @param treesize  size of the processtree
 * @return process index if succeeded otherwise -1
 */
static int _findProcess(int pid, ProcessTree_T *pt, int size) {
        if (size > 0) {
                for (int i = 0; i < size; i++)
                        if (pid == pt[i].pid)
                                return i;
        }
        return -1;
}


/**
 * Fill data in the process tree by recursively walking through it
 * @param pt process tree
 * @param i process index
 */
static void _fillProcessTree(ProcessTree_T *pt, int index) {
        if (! pt[index].visited) {
                pt[index].visited = true;
                pt[index].children.total = pt[index].children.count;
                pt[index].threads.children = 0;
                pt[index].cpu.usage.children = 0.;
                pt[index].memory.usage_total = pt[index].memory.usage;
                pt[index].filedescriptors.usage_total = pt[index].filedescriptors.usage;
                for (int i = 0; i < pt[index].children.count; i++) {
                        _fillProcessTree(pt, pt[index].children.list[i]);
                }
                if (pt[index].parent != -1 && pt[index].parent != index) {
                        ProcessTree_T *parent_pt = &pt[pt[index].parent];
                        parent_pt->children.total += pt[index].children.total;
                        parent_pt->threads.children += (pt[index].threads.self > 1 ? pt[index].threads.self : 1) + (pt[index].threads.children > 0 ? pt[index].threads.children : 0);
                        if (pt[index].cpu.usage.self >= 0) {
                                parent_pt->cpu.usage.children += pt[index].cpu.usage.self;
                        }
                        if (pt[index].cpu.usage.children >= 0) {
                                parent_pt->cpu.usage.children += pt[index].cpu.usage.children;
                        }
                        parent_pt->memory.usage_total     += pt[index].memory.usage_total;
                        parent_pt->filedescriptors.usage_total += pt[index].filedescriptors.usage_total;
                }
        }
}


/**
 * Adjust the CPU usage based on the available system resources: number of CPU cores the application may utilize. Single threaded application may utilized only one CPU core, 4 threaded application 4 cores, etc.. If the application
 * has more threads then the machine has cores, it is limited by number of cores, not threads.
 * @param now Current process information
 * @param prev Process information from previous cycle
 * @param delta The delta of system time between current and previous cycle
 * @return Process's CPU usage [%] since last cycle
 */
static float _cpuUsage(float rawUsage, unsigned int threads) {
        if (systeminfo.cpu.count > 0 && rawUsage > 0) {
                int divisor;
                if (threads > 1) {
                        if (threads >= (unsigned)systeminfo.cpu.count) {
                                // Multithreaded application with more threads then CPU cores
                                divisor = systeminfo.cpu.count;
                        } else {
                                // Multithreaded application with less threads then CPU cores
                                divisor = threads;
                        }
                } else {
                        // Single threaded application
                        divisor = 1;
                }
                float usage = rawUsage / divisor;
                return usage > 100. ? 100. : usage;
        }
        return 0.;
}


static int _match(regex_t *regex) {
        int found = -1;
        // Scan the whole process tree and find the oldest matching process whose parent doesn't match the pattern
        for (int i = 0; i < ptreesize; i++)
                if (ptree[i].cmdline && regexec(regex, ptree[i].cmdline, 0, NULL, 0) == 0 && (i == ptree[i].parent || ! ptree[ptree[i].parent].cmdline || regexec(regex, ptree[ptree[i].parent].cmdline, 0, NULL, 0) != 0) && (found == -1 || ptree[found].uptime < ptree[i].uptime))
                        found = i;
        return found >= 0 ? ptree[found].pid : -1;
}


/* ------------------------------------------------------------------ Public */


/**
 * Initialize the process tree
 * @return treesize >= 0 if succeeded otherwise < 0
 */
int ProcessTree_init(ProcessEngine_Flags pflags) {
        ProcessTree_T *oldptree = ptree;
        int oldptreesize = ptreesize;
        if (oldptree) {
                ptree = NULL;
                ptreesize = 0;
                // We need only process's cpu.time from the old ptree, so free dynamically allocated parts which we don't need before initializing new ptree (so the memory can be reused, otherwise the memory footprint will hold two ptrees)
                for (int i = 0; i < oldptreesize; i++) {
                        FREE(oldptree[i].cmdline);
                        FREE(oldptree[i].children.list);
                        FREE(oldptree[i].secattr);
                }
        }

        systeminfo.time_prev = systeminfo.time;
        systeminfo.time = Time_milli() / 100.;
        if ((ptreesize = init_processtree_sysdep(&ptree, pflags)) <= 0 || ! ptree) {
                DEBUG("System statistic -- cannot initialize the process tree -- process resource monitoring disabled\n");
                Run.flags &= ~Run_ProcessEngineEnabled;
                if (oldptree)
                        _delete(&oldptree, &oldptreesize);
                return -1;
        } else if (! (Run.flags & Run_ProcessEngineEnabled)) {
                DEBUG("System statistic -- initialization of the process tree succeeded -- process resource monitoring enabled\n");
                Run.flags |= Run_ProcessEngineEnabled;
        }

        int root = -1; // Main process. Not all systems have main process with PID 1 (such as Solaris zones and FreeBSD jails), so we try to find process which is parent of itself
        ProcessTree_T *pt = ptree;
        double time_delta = systeminfo.time - systeminfo.time_prev;
        for (int i = 0; i < (volatile int)ptreesize; i ++) {
                pt[i].cpu.usage.self = -1;
                if (oldptree) {
                        int oldentry = _findProcess(pt[i].pid, oldptree, oldptreesize);
                        if (oldentry != -1) {
                                if (systeminfo.cpu.count > 0 && time_delta > 0 && oldptree[oldentry].cpu.time >= 0 && pt[i].cpu.time >= oldptree[oldentry].cpu.time) {
                                        pt[i].cpu.usage.self = 100. * (pt[i].cpu.time - oldptree[oldentry].cpu.time) / time_delta;
                                }
                        }
                }
                // Note: on DragonFly, main process is swapper with pid 0 and ppid -1, so take also this case into consideration
                if ((pt[i].pid == pt[i].ppid) || (pt[i].ppid == -1)) {
                        root = pt[i].parent = i;
                } else {
                        // Find this process's parent
                        int parent = _findProcess(pt[i].ppid, pt, ptreesize);
                        if (parent == -1) {
                                /* Parent process wasn't found - on Linux this is normal: main process with PID 0 is not listed, similarly in FreeBSD jail.
                                 * We create virtual process entry for missing parent so we can have full tree-like structure with root. */
                                parent = ptreesize++;
                                pt = RESIZE(ptree, ptreesize * sizeof(ProcessTree_T));
                                memset(&pt[parent], 0, sizeof(ProcessTree_T));
                                root = pt[parent].ppid = pt[parent].pid = pt[i].ppid;
                        }
                        pt[i].parent = parent;
                        // Connect the child (this process) to the parent
                        RESIZE(pt[parent].children.list, sizeof(int) * (pt[parent].children.count + 1));
                        pt[parent].children.list[pt[parent].children.count] = i;
                        pt[parent].children.count++;
                }
        }
        FREE(oldptree); // Free the rest of old ptree
        if (root == -1) {
                DEBUG("System statistic error -- cannot find root process id\n");
                _delete(&ptree, &ptreesize);
                return -1;
        }

        _fillProcessTree(pt, root);

        return ptreesize;
}


/**
 * Delete the process tree
 */
void ProcessTree_delete(void) {
        _delete(&ptree, &ptreesize);
}


bool ProcessTree_updateProcess(Service_T s, pid_t pid) {
        ASSERT(s);

        /* save the previous pid and set actual one */
        s->inf.process->_pid = s->inf.process->pid;
        s->inf.process->pid  = pid;

        int leaf = _findProcess(pid, ptree, ptreesize);
        if (leaf != -1) {
                /* save the previous ppid and set actual one */
                s->inf.process->_ppid             = s->inf.process->ppid;
                s->inf.process->ppid              = ptree[leaf].ppid;
                s->inf.process->uid               = ptree[leaf].cred.uid;
                s->inf.process->euid              = ptree[leaf].cred.euid;
                s->inf.process->gid               = ptree[leaf].cred.gid;
                s->inf.process->uptime            = ptree[leaf].uptime;
                s->inf.process->threads           = ptree[leaf].threads.self;
                s->inf.process->children          = ptree[leaf].children.total;
                s->inf.process->zombie            = ptree[leaf].zombie;
                snprintf(s->inf.process->secattr, STRLEN, "%s", NVLSTR(ptree[leaf].secattr));
                if (ptree[leaf].cpu.usage.self >= 0) {
                        // compute only if initialized (delta between current and previous snapshot is available)
                        s->inf.process->cpu_percent = _cpuUsage(ptree[leaf].cpu.usage.self, ptree[leaf].threads.self);
                        s->inf.process->total_cpu_percent = s->inf.process->cpu_percent + _cpuUsage(ptree[leaf].cpu.usage.children, ptree[leaf].threads.children);
                        if (s->inf.process->total_cpu_percent > 100.) {
                                s->inf.process->total_cpu_percent = 100.;
                        }
                } else {
                        s->inf.process->cpu_percent = -1;
                        s->inf.process->total_cpu_percent = -1;
                }
                s->inf.process->mem               = ptree[leaf].memory.usage;
                s->inf.process->total_mem         = ptree[leaf].memory.usage_total;
                s->inf.process->filedescriptors.open        = ptree[leaf].filedescriptors.usage;
                s->inf.process->filedescriptors.openTotal   = ptree[leaf].filedescriptors.usage_total;
                s->inf.process->filedescriptors.limit.soft  = ptree[leaf].filedescriptors.limit.soft;
                s->inf.process->filedescriptors.limit.hard  = ptree[leaf].filedescriptors.limit.hard;
                if (systeminfo.memory.size > 0) {
                        s->inf.process->total_mem_percent = ptree[leaf].memory.usage_total >= systeminfo.memory.size ? 100. : (100. * (double)ptree[leaf].memory.usage_total / (double)systeminfo.memory.size);
                        s->inf.process->mem_percent       = ptree[leaf].memory.usage >= systeminfo.memory.size ? 100. : (100. * (double)ptree[leaf].memory.usage / (double)systeminfo.memory.size);
                }
                if (ptree[leaf].read.bytes >= 0)
                        Statistics_update(&(s->inf.process->read.bytes), ptree[leaf].read.time, ptree[leaf].read.bytes);
                if (ptree[leaf].read.bytesPhysical >= 0)
                        Statistics_update(&(s->inf.process->read.bytesPhysical), ptree[leaf].read.time, ptree[leaf].read.bytesPhysical);
                if (ptree[leaf].read.operations >= 0)
                        Statistics_update(&(s->inf.process->read.operations), ptree[leaf].read.time, ptree[leaf].read.operations);
                if (ptree[leaf].write.bytes >= 0)
                        Statistics_update(&(s->inf.process->write.bytes), ptree[leaf].write.time, ptree[leaf].write.bytes);
                if (ptree[leaf].write.bytesPhysical >= 0)
                        Statistics_update(&(s->inf.process->write.bytesPhysical), ptree[leaf].write.time, ptree[leaf].write.bytesPhysical);
                if (ptree[leaf].write.operations >= 0)
                        Statistics_update(&(s->inf.process->write.operations), ptree[leaf].write.time, ptree[leaf].write.operations);
                return true;
        }
        Util_resetInfo(s);
        return false;
}


time_t ProcessTree_getProcessUptime(pid_t pid) {
        if (ptree) {
                int leaf = _findProcess(pid, ptree, ptreesize);
                return (time_t)((leaf >= 0 && leaf < ptreesize) ? ptree[leaf].uptime : -1);
        }
        return 0;
}


pid_t ProcessTree_findProcess(Service_T s) {
        ASSERT(s);
        // Test the cached PID first
        if (s->inf.process->pid > 0) {
                errno = 0;
                if (getpgid(s->inf.process->pid) > -1 || errno == EPERM)
                        return s->inf.process->pid;
        }
        // If the cached PID is not running, scan for the process again
        if (s->matchlist) {
                // Update the process tree including command line
                ProcessTree_init(ProcessEngine_CollectCommandLine);
                if (Run.flags & Run_ProcessEngineEnabled) {
                        int pid = _match(s->matchlist->regex_comp);
                        if (pid >= 0)
                                return pid;
                } else {
                        DEBUG("Process information not available -- skipping service %s process existence check for this cycle\n", s->name);
                        // Return value is NOOP - it is based on existing errors bitmap so we don't generate false recovery/failures
                        return ! (s->error & Event_NonExist);
                }
        } else {
                pid_t pid = Util_getPid(s->path);
                if (pid > 0) {
                        errno = 0;
                        if (getpgid(pid) > -1 || errno == EPERM)
                                return pid;
                        DEBUG("'%s' process test failed [pid=%d] -- %s\n", s->name, pid, STRERROR);
                }
        }
        Util_resetInfo(s);
        return 0;
}


void ProcessTree_testMatch(char *pattern) {
        regex_t *regex_comp;
        int reg_return;

        NEW(regex_comp);
        if ((reg_return = regcomp(regex_comp, pattern, REG_NOSUB|REG_EXTENDED))) {
                char errbuf[STRLEN];
                regerror(reg_return, regex_comp, errbuf, STRLEN);
                regfree(regex_comp);
                FREE(regex_comp);
                printf("Regex %s parsing error: %s\n", pattern, errbuf);
                exit(1);
        }
        ProcessTree_init(ProcessEngine_CollectCommandLine);
        if (Run.flags & Run_ProcessEngineEnabled) {
                int count = 0;
                printf("List of processes matching pattern \"%s\":\n", pattern);
                StringBuffer_T output = StringBuffer_create(256);
                TextBox_T t = TextBox_new(output, 4, (TextBoxColumn_T []){
                                {.name = "",        .width = 1,  .wrap = false, .align = TextBoxAlign_Left},
                                {.name = "PID",     .width = 8,  .wrap = false, .align = TextBoxAlign_Right},
                                {.name = "PPID",    .width = 8,  .wrap = false, .align = TextBoxAlign_Right},
                                {.name = "Command", .width = 50, .wrap = true,  .align = TextBoxAlign_Left}
                          }, true);
                // Select the process matching the pattern
                int pid = _match(regex_comp);
                // Print all matching processes and highlight the one which is selected
                for (int i = 0; i < ptreesize; i++) {
                        if (ptree[i].cmdline && ! strstr(ptree[i].cmdline, "procmatch")) {
                                if (! regexec(regex_comp, ptree[i].cmdline, 0, NULL, 0)) {
                                        if (pid == ptree[i].pid) {
                                                TextBox_setColumn(t, 1, COLOR_BOLD "*" COLOR_RESET);
                                                TextBox_setColumn(t, 2, COLOR_BOLD "%d" COLOR_RESET, ptree[i].pid);
                                                TextBox_setColumn(t, 3, COLOR_BOLD "%d" COLOR_RESET, ptree[i].ppid);
                                                TextBox_setColumn(t, 4, COLOR_BOLD "%s" COLOR_RESET, ptree[i].cmdline);
                                        } else {
                                                TextBox_setColumn(t, 2, "%d", ptree[i].pid);
                                                TextBox_setColumn(t, 3, "%d", ptree[i].ppid);
                                                TextBox_setColumn(t, 4, "%s", ptree[i].cmdline);
                                        }
                                        TextBox_printRow(t);
                                        count++;
                                }
                        }
                }
                TextBox_free(&t);
                if (Run.flags & Run_Batch || ! TextColor_support())
                        TextColor_strip(TextBox_strip((char *)StringBuffer_toString(output)));
                printf("%s", StringBuffer_toString(output));
                StringBuffer_free(&output);
                printf("Total matches: %d\n", count);
                if (count > 1)
                        printf("\n"
                               "WARNING:\n"
                               "Multiple processes match the pattern. Monit will select the process with the\n"
                               "highest uptime, the one highlighted.\n");
        }
        regfree(regex_comp);
        FREE(regex_comp);
}
