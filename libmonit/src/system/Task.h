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


#ifndef TASK_INCLUDED
#define TASK_INCLUDED


/**
 * A <b>Task</b> represents work executed by a <b>Scheduler</b>.
 * A new Task is created with Scheduler_task() and started with
 * Task_start(). A started Task can be canceled at any time by
 * using Task_cancel(), after which the Task object is returned to
 * the Scheduler for reuse and the caller should no longer use it.
 * You can also modify properties of a task and then reschedule the
 * task with Task_restart().
 *
 * <h3>Task Properties</h3>
 * <ul>
 * <li>A <b>one-time</b> task is specified with Task_once().
 * Time is in seconds and specify how long the Scheduler
 * should wait before it will execute the task. For instance to
 * execute a task once, 5 seconds from now, use Task_once(5.0).
 * A one-time Task is executed exactly one time. Despite its name,
 * a one-time task is normally reused and restarted within the worker.
 * Such tasks are often used for timeout operations. If the Task
 * is not needed anymore call Task_cancel() to return the Task to
 * the Scheduler for reuse.
 *
 * <li>A <b>periodic</b> task is specified with Task_periodic().
 * A periodic task runs continuously with a set interval. Two values are
 * used: <i>offset</i> specify the offset of the hour and <i>interval</i>,
 * how often the task should run. For example, to specify a task that
 * should run at the top of every hour, use Task_periodic(0, 3600).
 * To specify a periodic task that should run half-past every hour, e.g.
 * 10:30, 11:30, 12:30 etc, use Task_periodic(1800, 3600).
 *
 * <li>A <b>one-time</b> task to be run <b>at</b> a specific time is specified
 * with Task_at(). In difference to the above tasks an <b>at</b> task uses
 * wall-clock time to specify when to run. For example,
 * Task_at(Time_parse("2019-12-28 00:12:58")). An <i>at</i> Task is executed
 * exactly one time. The Task can be restarted at a later time if needed
 * again, otherwise cancel the Task with Task_cancel() so it can be returned
 * to the Scheduler and reused.
 *
 * <li>You can change the time or offset of any Task and reschedule or
 * restart the task. A one-time task such as an <code>at</code> or a
 * <code>once</code> task must be restarted to run again. If not needed
 * anymore, call Task_cancel() to return the Task to the Scheduler for
 * reuse.
 *
 * <li>Use Task_setData() to associate <b>data</b> with a Task and
 * Task_getData() to access the data.
 *
 * <li>Use Task_setWorker() to set the callback-function for a Task. The
 * Scheduler calls this function to perform the actual <b>work</b> of the Task.
 * </ul>
 *
 * @see Scheduler.h
 * @author https://www.tildeslash.com/
 * @see https://www.mmonit.com/
 * @file
 */


#define T Task_T
typedef struct T *T;

/** @name Initialization */
//@{

/**
 * Specifies a one-time task. I.e. the task is scheduled for
 * execution once and only once. The worker callback function
 * can rescehdule and call Task_restart() to restart the task,
 * otherwise cancel the Task after the worker finish with
 * Task_cancel() so it can be reused by the Scheduler.
 * Example: to start the task 5 seconds from now use Task_once(5.)
 * The value is specified in seconds, but fractions of seconds can
 * be used to specify a shorter time. For instance to specify a task
 * that will start 10 milliseconds from now, use, Task_once(0.01)
 * @param t Task object
 * @param offset Number of seconds until the Scheduler should
 * run the task after it has been started (or restarted).
 */
void Task_once(T t, double offset);


/**
 * Specifies a periodic task. I.e. the task is to be scheduled for periodic
 * execution. The offset parameter specify the offset within interval
 * for when the task should run and interval specify the next time the task
 * should run. For example to run the task 5 minutes past every hour, e.g.
 * 10:05, 11:05, 12:05 etc. use Task_periodic(300, 3600.) where 300 = 5 min
 * and 3600 = 1 hour.
 * @param t Task object
 * @param offset within interval for when the task should run. Value in
 * seconds. Typical values for offset are something between 0 and interval
 * @param interval Task interval in seconds (value > 0)
 */
void Task_periodic(T t, double offset, double interval);


/**
 * Specifies a one-time task to be run <b>at</b> a specific time. The
 * task is scheduled for execution once and only once at the specified time.
 * The Task can be rescheduled and restarted with Task_restart(). Use
 * Task_cancel() if the Task is not needed anymore so it can be reused by
 * the Scheduler. Example: Task_at(Time_parse("Fri, 29 Jan 2011 at 09:05:00")).
 * @param t Task object
 * @param time The time (number of seconds since the EPOCH) to start
 * the task.
 */
void Task_at(T t, time_t time);


//@}

/** @name Properties */
//@{

/**
 * Returns the Task's descriptive name.
 * @param t Task object
 * @return The Task's descriptive name.
 */
const char *Task_getName(T t);


/**
 * Set optional <code>data</code> associated with this Task
 * @param t Task object.
 * @param data The data to be associated with this Task
 */
void Task_setData(T t, void *data);


/**
 * Returns the <code>data</code> associated with this Task
 * @param t Task object.
 * @return The data associated with this Task
 */
void *Task_getData(T t);


/**
 * Returns the Task offset time
 * @param t A 'Task object.
 * @return Task offset time in seconds
 */
double Task_getOffset(T t);


/**
 * Returns the Task's interval time. Interval for a one-time task is 0.
 * @param t Task object.
 * @return The Task's interval time in seconds
 */
double Task_getInterval(T t);


/**
 * Returns true if the Task was started otherwise false
 * @param t Task object.
 * @return True if Task was started otherwise false
 */
bool Task_isStarted(T t);


/**
 * Set the Task's worker function. The Scheduler calls this function
 * to run the task. The <i>worker</i>function should take one parameter
 * which is the task object. This property is required.
 * @param t Task object
 * @param worker A method which implements the work performed by the Task
 */
void Task_setWorker(T t, void (*worker)(T t));


/**
 * Returns the time (as seconds since the EPOCH) when the Scheduler last
 * started the Task. If the Task has not yet been executed, 0 is returned.
 * @param t Task object.
 * @return The time of last Task execution
 */
time_t Task_lastRun(T t);


/**
 * Returns the time (as seconds since the EPOCH) when the Scheduler will
 * start the Task. If the Task is stopped, 0 is returned.
 * @param t An Task object
 * @return The time of next Task execution
 */
time_t Task_nextRun(T t);


//@}


/**
 * Start the task
 * @param t A Task object
 * @exception AssertException if the task has not been initialized with one of
 * Task_once(), Task_periodic() or Task_at() or if the Task's worker is not set
 * or if the Task has already been started
 * @see Task.h
 */
void Task_start(T t);


/**
 * Cancel the task and return the object to the Scheduler for reuse
 * @param t A Task object
 * @exception AssertException if the task has already been canceled
 */
void Task_cancel(T t);


/**
 * Restart the task. Only a started Task might be restarted and it is a
 * checked runtime error to try to restart a canceled task.
 * @param t A Task object
 * @exception AssertException if the task has not previously been started
 * with Task_start() or if the Task is canceled.
 
 */
void Task_restart(T t);


#undef T
#endif
