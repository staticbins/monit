/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
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


#ifndef SCHEDULER_INCLUDED
#define SCHEDULER_INCLUDED

/**
 * A <b>Scheduler</b> is used to execute work in a timely fashion. In UNIX 
 * terminology, a Scheduler provides the functionality of both at(1) and 
 * cron(8) programatically. The work to be executed by a Scheduler is 
 * represented by a Task object. A new Task is created with Scheduler_task()
 * and started with Task_start(). Task properties must be set before the
 * Task is started. This include; when the Task should start and the callback
 * function which will perform the actual work of the Task.
 * See Task.h for details.
 *
 * A Scheduler run in its own thread and maintains a timer loop for 
 * scheduling. A worker thread pool (Dispatcher.h) is used internally by 
 * the Scheduler to run tasks. The number of worker threads the Dispatcher
 * should use is set at creation time in Scheduler_new(). It is recommended
 * to use the same number as the number of CPU cores on the system. If more
 * concurrency is required, i.e. if you notice that some tasks are executed
 * later than they should, moderately increase the number of worker threads.
 * 
 * <i>This class is thread-safe</i>
 *
 * @see Task.h
 * @author https://www.tildeslash.com/
 * @see https://www.mmonit.com/
 * @file
 */


#define T Scheduler_T
typedef struct T *T;


/**
 * Create a new Scheduler
 * @param workers The maximum number of threads that should be used to
 * process tasks. Use the same number as CPU cores on the system and
 * only increase moderately if more concurrency is required.
 * @return A new Scheduler object
 * @exception AssertException if initializing failed
 */
T Scheduler_new(int workers);


/**
 * Destroy the Scheduler. Stop and release all tasks.
 * @param S A Scheduler object reference
 */
void Scheduler_free(T *S);


/**
 * Create a new empty Task object. Properties of the Task must be 
 * configured before the Task is started with Task_start().
 * @param S A Scheduler object
 * @param name A short descriptive name for the task. Max 20
 * chars will be copied and used as the Task name. 
 * @return Task object.
 * @see Task.h
 */
Task_T Scheduler_task(T S, const char *name);


#undef T
#endif

