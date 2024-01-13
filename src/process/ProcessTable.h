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

#ifndef MONIT_PROCESSTREE_H
#define MONIT_PROCESSTREE_H

#include "util/Array.h"

/**
 * A <b>ProcessTable</b> holds all running processes on the system.
 * Each process in the table is of type <b>process_t</b> and holds
 * information about that process and its resource usage. This table
 * is thread-safe.
 *
 * @author https://www.tildeslash.com/
 * @see https://www.mmonit.com/
 * @file
 */

// MARK: - Definitions

// TODO: Check if we can remove stuff or change stuff
typedef struct process_t {
        bool zombie;
        pid_t pid;
        pid_t ppid;
        struct {
                int uid;
                int euid;
                int gid;
        } cred;
        struct {
                struct {
                        float self;
                        float children;
                } usage;
                double time;
        } cpu;
        struct {
                int self;
                int children;
        } threads;
        struct {
                int count;
                int total;
        } children;
        struct {
                unsigned long long usage;
                unsigned long long usage_total;
        } memory;
        struct {
                unsigned long long time;
                long long bytes;
                long long bytesPhysical;
                long long operations;
                double rbytesps;
        } read;
        struct {
                unsigned long long time;
                long long bytes;
                long long bytesPhysical;
                long long operations;
                double wbytesps;
        } write;
        time_t uptime;
        char *cmdline;
        char *secattr;
        struct {
                long long usage;
                long long usage_total;
                struct {
                        long long soft;
                        long long hard;
                } limit;
        } filedescriptors;
} *process_t;

#define T ProcessTable_T
typedef struct T {
        int size;
        pid_t self_pid;
        Mutex_T mutex;
        Array_T cache;
        process_t table;
        ProcessEngine_Flags options;
} *T;

typedef enum {
        ProcessTableSort_Pid = 0,
        ProcessTableSort_Cpu,
        ProcessTableSort_Mem,
        ProcessTableSort_Dsk,
        ProcessTableSort_Last
} ProcessTableSort_Type;

// MARK: - Public methods
T ProcessTable_new(void);
void ProcessTable_free(T *P);
bool ProcessTable_update(T P);
time_t ProcessTable_uptime(T P, pid_t pid);
void ProcessTable_map(T P, void (*apply)(process_t process, void *ap), void *ap);
void ProcessTable_sort(T P, ProcessTableSort_Type sort, void (*apply)(process_t process, void *ap), void *ap);
// Process_T cache
void ProcessTable_setProcess(T P, Process_T process);
Process_T ProcessTable_getProcess(T P, pid_t pid);
Process_T ProcessTable_findProcess(T P, const char *name);
Process_T ProcessTable_removeProcess(T P, pid_t pid);
// MARK: - Class methods
bool ProcessTable_exist(pid_t pid);
// MARK: - Service methods
pid_t ProcessTable_findServiceProcess(Service_T s);
bool ProcessTable_updateServiceProcess(T P, Service_T s, pid_t pid);

#undef T
#endif

