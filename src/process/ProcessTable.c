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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <stdlib.h>

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
#include "process_sysdep.h"
#include "ProcessTable.h"

// libmonit
#include "util/Str.h"
#include "system/Time.h"
#include "exceptions/AssertException.h"



// MARK: - Definitions


#define T ProcessTable_T


// MARK: - Private methods


static void _freeCachedProcesses(__attribute__ ((unused))int key, void **value, __attribute__ ((unused))void *ap) {
        Process_T p = *value;
        Process_detach(p);
        Process_free(&p);
}


// Predicator function for looking up a Process_T given a Service name
static bool _compareName(void *value, void *name) {
        Process_T p = value;
        return Str_isEqual(Process_name(p), name);
}


static inline void _prune(process_t process, __attribute__ ((unused))void *ap) {
        FREE(process->cmdline);
        FREE(process->secattr);
}


static inline void _delete(process_t table, int *size) {
        int length = *size;
        for (int i = 0; i < length; i++) {
                _prune(&table[i], NULL);
        }
        FREE(table);
        *size = 0;
}


static inline void _map(T P, void (*apply)(process_t process, void *ap), void *ap) {
        for (int i = 0; i < P->size; i++) {
                apply(&P->table[i], ap);
        }
}


static inline process_t _find(T P, pid_t pid) {
        for (int i = 0; i < P->size; i++)
                if (pid == P->table[i].pid)
                        return &P->table[i];
        return NULL;
}


static inline int _findIndex(T P, pid_t pid) {
        for (int i = 0; i < P->size; i++)
                if (pid == P->table[i].pid)
                        return i;
        return -1;
}


static int _sortPidAsc(const void *x, const void *y) {
        const struct process_t *a = x;
        const struct process_t * b = y;
        return (int)(a->pid - b->pid);
}


static int _sortCpuDesc(const void *x, const void *y) {
        double a = ((process_t)x)->cpu.usage.self;
        double b = ((process_t)y)->cpu.usage.self;
        if (b > a) return 1;
        if (b < a) return -1;
        return 0;
}


static int _sortMemDesc(const void *x, const void *y) {
        uint64_t a = ((process_t)x)->memory.usage_total;
        uint64_t b = ((process_t)y)->memory.usage_total;
        if (b > a) return 1;
        if (b < a) return -1;
        return 0;
}


static int _sortDiskDesc(const void *x, const void *y) {
        double a = ((process_t)x)->write.wbytesps + ((process_t)x)->read.rbytesps;
        double b = ((process_t)y)->write.wbytesps + ((process_t)y)->read.rbytesps;
        if (b > a) return 1;
        if (b < a) return -1;
        return 0;
}


// Scan the process table and find the oldest matching process whose
// parent doesn't match the pattern. Returns the pid if found or -1
// Precondition, we cannot assume any order of the table as it might
// have been sorted. Also, while OSs generally have older processes with
// a lower pid number, there is no guarantee as pids might be reused
static pid_t _match(T P, regex_t *regex) {
        assert(P);
        pid_t pid = -1;
        int found = 0;
        LOCK(P->mutex)
        {
                for (int i = 0; i < P->size ; i++) {
                        struct process_t process = P->table[i];
                        if (process.pid == P->self_pid)
                                continue;
                        if (STR_DEF(process.cmdline)) {
                                if (regexec(regex, process.cmdline, 0, NULL, 0) == 0) {
                                        if (process.ppid > 1) {
                                                int parent = _findIndex(P, process.ppid);
                                                if (parent > 0 ) {
                                                        if (STR_DEF(P->table[parent].cmdline)) {
                                                                if (regexec(regex, P->table[parent].cmdline, 0, NULL, 0) == 0)
                                                                        continue;
                                                        }
                                                }
                                        }
                                        if (found) {
                                                if (P->table[found].uptime > P->table[i].uptime)
                                                        continue;
                                        }
                                        found = i;
                                        pid = P->table[i].pid;
                                }
                        }
                }
        }
        END_LOCK;
        return pid;
}


static void _calculateCpuUsage(process_t prev, process_t current) {
        //double normalizer = current->threads.self > 1
        //? current->threads.self > System_Info.cpu.count
        //? System_Info.cpu.count : current->threads.self
        //: 1;
        double deltaTime = (System_Info.time - System_Info.time_prev);
        if (deltaTime > 0) {
                double deltaCpuTime = (current->cpu.time - prev->cpu.time) * 100;
                //current->cpu.usage.self = (100.0 * (deltaCpuTime / deltaTime)) / normalizer;
                current->cpu.usage.self = (100.0 * (deltaCpuTime / deltaTime));
        }
}


static void _calculateDiskIO(process_t prev, process_t current) {
        uint64_t deltaTime = current->write.time - prev->write.time;
        if (deltaTime > 0) {
                current->write.wbytesps = (current->write.bytesPhysical - prev->write.bytesPhysical) * 1000.0 / deltaTime;
                current->read.rbytesps = (current->read.bytesPhysical - prev->read.bytesPhysical) * 1000.0 / deltaTime;
        }
}


static void _calculateResourceUsage(process_t prev, process_t current) {
        _calculateCpuUsage(prev, current);
        _calculateDiskIO(prev, current);
        current->memory.usage_total += current->memory.usage;
}


static inline void _aggregateParentUsage(process_t parent, process_t achild) {
        parent->children.total += 1;
        parent->threads.children += achild->threads.self;
        parent->cpu.usage.children += achild->cpu.usage.self;
        parent->memory.usage_total += achild->memory.usage;
        parent->filedescriptors.usage_total += achild->filedescriptors.usage;
}


static bool _buildProcessTable(T P) {
        int size = 0;
        if ((size = init_processtree_sysdep(&P->table, P->options)) <= 0) {
                DEBUG("System statistic -- cannot initialize the process table -- process resource monitoring disabled\n");
                Run.flags &= ~Run_ProcessEngineEnabled;
                return false;
        } else if (! (Run.flags & Run_ProcessEngineEnabled)) {
                DEBUG("System statistic -- initialization of the process table succeeded -- process resource monitoring enabled\n");
                Run.flags |= Run_ProcessEngineEnabled;
        }
        P->size = size;
        return true;
}


static bool _updateProcessTable(T P) {
        int prevSize = P->size;
        process_t prev = P->table;
        // Free node allocations before allocating a new table
        _map(P, _prune, NULL);
        if (!_buildProcessTable(P)) {
                DEBUG("System statistic -- cannot update the process table\n");
                return false;
        }
        System_Info.time_prev = System_Info.time;
        System_Info.time = Time_milli() / 100.;
        for (int i = 0; i < prevSize; i++) {
                // Update current processes resource usage
                process_t current = _find(P, prev[i].pid);
                if (current) {
                        _calculateResourceUsage(&prev[i], current);
                }
        }
        FREE(prev);
        // Aggregate child resource usage into parent. The table is already sorted
        // ascending on pid. Start with leafs and work backwards towards the root.
        for (int i = (int)(P->size - 1); i >= 0 ; i--) {
                if (P->table[i].pid == P->table[i].ppid)
                        continue;
                if (P->table[i].ppid > 1) { // Don't bother to aggregate into "init"
                        process_t parent = _find(P, P->table[i].ppid);
                        if (parent) {
                                _aggregateParentUsage(parent, &P->table[i]);
                        }
                }
        }
        return true;
}


// MARK: - Public methods


T ProcessTable_new(void) {
        T P;
        NEW(P);
        Mutex_init(P->mutex);
        P->self_pid = getpid();
        P->options = ProcessEngine_CollectCommandLine;
        if (!_buildProcessTable(P)) {
                ProcessTable_free(&P);
        } else {
                P->cache = Array_new(263);
        }
        return P;
}


void ProcessTable_free(T *P) {
        assert(P && *P);
        _delete((*P)->table, &(*P)->size);
        Array_map((*P)->cache, _freeCachedProcesses, NULL);
        Array_free(&(*P)->cache);
        Mutex_destroy((*P)->mutex);
        FREE(*P);
}


bool ProcessTable_update(T P) {
        assert(P);
        Mutex_lock(P->mutex);
        bool result = _updateProcessTable(P);
        if (!result)
                _delete(P->table, &P->size);
        Mutex_unlock(P->mutex);
        return result;
}


// The apply function is called under a table lock and must be fast.
// It should not do any i/o or stuff that might block
void ProcessTable_map(T P, void (*apply)(process_t process, void *ap), void *ap) {
        assert(P);
        LOCK(P->mutex)
        {
                _map(P, apply, ap);
        }
        END_LOCK;
}


time_t ProcessTable_uptime(T P, pid_t pid) {
        time_t t = 0;
        LOCK(P->mutex)
        {
                process_t p = _find(P, pid);
                if (p) t = p->uptime;
        }
        END_LOCK;
        return t;
}


static int (*_sort[])(const void *x, const void *y) = {
        _sortPidAsc,
        _sortCpuDesc,
        _sortMemDesc,
        _sortDiskDesc
};
// The apply function is called under a table lock and must be fast.
// It should not do any i/o or stuff that might block
void ProcessTable_sort(T P, ProcessTableSort_Type func, void (*apply)(process_t process, void *ap), void *ap) {
        assert(P);
        LOCK(P->mutex)
        {
                qsort(P->table, P->size, sizeof(struct process_t), _sort[func]);
                _map(P, apply, ap);
        }
        END_LOCK;
}


// MARK: - Process_T cache


void ProcessTable_setProcess(T P, Process_T process) {
        assert(P);
        assert(process);
        Process_T p = NULL;
        LOCK(P->mutex)
        {
                p = Array_put(P->cache, Process_pid(process), process);
        }
        END_LOCK;
        if (p) {
                // In the very unlikely case that a process already exist with
                // the same pid, we detach and free the process, unless it's
                // the same process, in witch case we just write a debug msg
                if (p != process) {
                        Process_detach(p);
                        Process_free(&p);
                } else {
                        DEBUG("ProcessTable_setProcess: Trying to store the same process again\n");
                }
        }
}


Process_T ProcessTable_getProcess(T P, pid_t pid) {
        assert(P);
        Process_T p = NULL;
        LOCK(P->mutex)
        {
                p = Array_get(P->cache, pid);
        }
        END_LOCK;
        return p;
}


// Find a cached Process_T given a service name
Process_T ProcessTable_findProcess(T P, const char *name) {
        assert(P);
        assert(name);
        Process_T p = NULL;
        LOCK(P->mutex)
        {
                p = Array_find(P->cache, _compareName, (void*)name);
        }
        END_LOCK;
        return p;
}


Process_T ProcessTable_removeProcess(T P, pid_t pid) {
        assert(P);
        Process_T p = NULL;
        LOCK(P->mutex)
        {
                p = Array_remove(P->cache, pid);
        }
        END_LOCK;
        return p;
}


// MARK: - Class methods


bool ProcessTable_exist(pid_t pid) {
        errno = 0;
        return ((pid >= 0) && (getpgid(pid) > -1 || errno == EPERM));
}


// MARK: - Service methods


pid_t ProcessTable_findServiceProcess(Service_T s) {
        assert(s);
        // Test the cached PID first
        if (s->inf.process->pid > 0) {
                if (ProcessTable_exist(s->inf.process->pid))
                        return s->inf.process->pid;
        }
        // If the cached PID is not running, scan for the process in the shared Process Table
        
        // TODO: Update Process_T with correct pid from match or from pid-file.
        // TODO: If pid-file is older than system boottime, ignore the pid
        if (s->matchlist) {
                if (Run.flags & Run_ProcessEngineEnabled) {
                        assert(Process_Table);
                        pid_t pid = _match(Process_Table, s->matchlist->regex_comp);
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
                        if (ProcessTable_exist(pid))
                                return pid;
                        DEBUG("'%s' process test failed [pid=%d] -- %s\n", s->name, pid, System_lastError());
                }
        }
        Util_resetInfo(s);
        return 0;
}


bool ProcessTable_updateServiceProcess(T P, Service_T s, pid_t pid) {
        assert(P);
        assert(s);
        /* save the previous pid and set actual one */
        s->inf.process->_pid = s->inf.process->pid;
        s->inf.process->pid  = pid;
        struct process_t process = {.pid = -1};
        // Minimize table lock to things that might change, then do a value copy of the struct
        // which can safely be used without locking
        LOCK(P->mutex)
        {
                process_t t = _find(P, pid);
                if (t) {
                        Str_copy(s->inf.process->secattr, NVLSTR(t->secattr), STRLEN);
                        process = *t;
                }
        }
        END_LOCK;
        if (process.pid != -1) {
                /* save the previous ppid and set actual one */
                s->inf.process->_ppid             = s->inf.process->ppid;
                s->inf.process->ppid              = process.ppid;
                s->inf.process->uid               = process.cred.uid;
                s->inf.process->euid              = process.cred.euid;
                s->inf.process->gid               = process.cred.gid;
                s->inf.process->uptime            = process.uptime;
                s->inf.process->threads           = process.threads.self;
                s->inf.process->children          = process.children.total;
                s->inf.process->zombie            = process.zombie;
                // TODO: Move this up to _calculateResourceUsage and just get the percent here from process
                if (process.cpu.usage.self >= 0) {
                        s->inf.process->cpu_percent = process.cpu.usage.self;
                        s->inf.process->total_cpu_percent = s->inf.process->cpu_percent + process.cpu.usage.children;
                        if (s->inf.process->total_cpu_percent > 100.) {
                                s->inf.process->total_cpu_percent = 100.;
                        }
                } else {
                        s->inf.process->cpu_percent = -1;
                        s->inf.process->total_cpu_percent = -1;
                }
                s->inf.process->mem                         = process.memory.usage;
                s->inf.process->total_mem                   = process.memory.usage_total;
                s->inf.process->filedescriptors.open        = process.filedescriptors.usage;
                s->inf.process->filedescriptors.openTotal   = process.filedescriptors.usage_total;
                s->inf.process->filedescriptors.limit.soft  = process.filedescriptors.limit.soft;
                s->inf.process->filedescriptors.limit.hard  = process.filedescriptors.limit.hard;
                if (System_Info.memory.size > 0) {
                        s->inf.process->total_mem_percent =
                        process.memory.usage_total >= System_Info.memory.size
                        ? 100.
                        : (100. * (double)process.memory.usage_total / (double)System_Info.memory.size);
                        s->inf.process->mem_percent =
                        process.memory.usage >= System_Info.memory.size
                        ? 100.
                        : (100. * (double)process.memory.usage / (double)System_Info.memory.size);
                }
                if (process.read.bytes >= 0)
                        Statistics_update(&(s->inf.process->read.bytes), process.read.time, process.read.bytes);
                if (process.read.bytesPhysical >= 0)
                        Statistics_update(&(s->inf.process->read.bytesPhysical), process.read.time, process.read.bytesPhysical);
                if (process.read.operations >= 0)
                        Statistics_update(&(s->inf.process->read.operations), process.read.time, process.read.operations);
                if (process.write.bytes >= 0)
                        Statistics_update(&(s->inf.process->write.bytes), process.write.time, process.write.bytes);
                if (process.write.bytesPhysical >= 0)
                        Statistics_update(&(s->inf.process->write.bytesPhysical), process.write.time, process.write.bytesPhysical);
                if (process.write.operations >= 0)
                        Statistics_update(&(s->inf.process->write.operations), process.write.time, process.write.operations);
                return true;
        }
        Util_resetInfo(s);
        return false;
}
