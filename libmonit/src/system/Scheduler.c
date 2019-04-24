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

#include "Config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdatomic.h>
#include "ev.h"

#include "Str.h"
#include "List.h"
#include "Thread.h"
#include "Dispatcher.h"
#include "system/Time.h"
#include "system/System.h"
#include "Task.h"
#include "Scheduler.h"


/**
 * Implementation of Scheduler and Task.
 *
 * This Scheduler is thread-safe.
 *
 * @author https://www.tildeslash.com/
 * @see https://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


#define T Scheduler_T

typedef enum {
        Task_None = 0,
        Task_Once,
        Task_At,
        Task_Periodic
} Task_Type;

typedef enum {
        Task_Initial = 0,
        Task_Started,
        Task_Canceled,
        Task_Limbo
} Task_Status;

struct T {
        struct ev_loop *loop;
        ev_async loop_notify;
        _Bool stopped;
        Mutex_T lock;
        Thread_T thread;
        List_T tasks;
        Dispatcher_T dispatcher;
};

struct Task_T {
        union {
                ev_periodic p;
                ev_timer t;
        } ev;
        char name[20];
        Task_Type type;
        void *data;
        double offset;
        double interval;
        Task_Status state;
        _Bool isavailable;
        void(*worker)(Task_T p);
        ev_tstamp executed;
        atomic_int inprogress;
        T scheduler;
};


/* --------------------------------------------------------------- Private */


static inline _Bool _available_task(void *e) {
        Task_T task = e;
        return (task && task->isavailable && !task->inprogress);
}


static inline void _dispatch(Task_T t) {
        int p = 0;
        if (atomic_compare_exchange_strong(&t->inprogress, &p, 1)) {
                t->executed = ev_now(t->scheduler->loop);
                if (! Dispatcher_add(t->scheduler->dispatcher, t))
                        ERROR("Scheduler: could not add task '%s' to the dispatcher\n", t->name);
        }
}


static void *_loop(void *t) {
        T scheduler = (T)t;
        LOCK(scheduler->lock)
        {
                ev_run(scheduler->loop, 0);
        }
        END_LOCK;
        return NULL;
}


static void _loop_release(EV_P) {
        T scheduler = (T)ev_userdata(EV_A);
        Mutex_unlock(scheduler->lock);
}


static void _loop_acquire(EV_P) {
        T scheduler = (T)ev_userdata(EV_A);
        Mutex_lock(scheduler->lock);
}


static void _loop_notify(EV_P_ ev_async *w, int revents) {
        T scheduler = (T)ev_userdata(EV_A);
        if (scheduler->stopped)
                ev_break(loop, EVBREAK_ALL);
}


static void _timer_cb(EV_P_ ev_timer *w, int revents) {
        Task_T t = (Task_T)w;
        ev_timer_stop(t->scheduler->loop, w);
        _dispatch(t);
}


static void _periodic_cb(EV_P_ ev_periodic *w, int revents) {
        _dispatch((Task_T)w);
}


static void _worker(void *t) {
        Task_T task = t;
        if (task->type == Task_Once || task->type == Task_At)
                task->state = Task_Limbo;
        TRY
        {
                task->worker(task);
        }
        ELSE
        {
                ERROR("Scheduler: task %s: %s: %s\n", task->name, Exception_frame.exception->name, Exception_frame.message);
        }
        FINALLY
        {
                if (task->state == Task_Limbo)
                        Task_cancel(task);
                atomic_store(&task->inprogress, 0);
        }
        END_TRY;
}


static void _start(T S) {
        assert(S);
        if (S->stopped) {
                S->stopped = false;
                DEBUG("Starting Scheduler\n");
                Thread_create(S->thread, _loop, S);
        }
}


static void _stop(T S) {
        assert(S);
        LOCK(S->lock)
        {
                S->stopped = true;
        }
        END_LOCK;
        ev_async_send(S->loop, &S->loop_notify);
        Thread_join(S->thread);
        while (List_length(S->tasks) > 0) {
                Task_T t = List_pop(S->tasks);
                FREE(t);
        }
        DEBUG("Scheduler stopped\n");
}


/* ---------------------------------------------------------------- Public */


T Scheduler_new(int workers) {
        T S;
        NEW(S);
        if (! (S->loop = ev_loop_new(EVFLAG_AUTO))) {
                FREE(S);
                THROW(AssertException, "Scheduler: cannot create the event loop\n");
        }
        Mutex_init(S->lock);
        ev_set_userdata(S->loop, S);
        ev_set_loop_release_cb(S->loop, _loop_release, _loop_acquire);
        ev_async_init(&S->loop_notify, _loop_notify);
        ev_async_start(S->loop, &S->loop_notify);
        S->tasks = List_new();
        S->dispatcher = Dispatcher_new(workers, 60, _worker);
        S->stopped = true;
        _start(S);
        return S;
}


void Scheduler_free(T *S) {
        assert(S && *S);
        _stop(*S);
        Dispatcher_free(&(*S)->dispatcher);
        ev_loop_destroy((*S)->loop);
        List_free(&(*S)->tasks);
        Mutex_destroy((*S)->lock);
        FREE(*S);
}


Task_T Scheduler_task(T S, const char *name) {
        assert(S);
        assert(name);
        Task_T task = NULL;
        LOCK(S->lock)
        {
                if (! S->stopped) {
                        task = List_find(S->tasks, _available_task);
                        if (task == NULL) {
                                NEW(task);
                                assert(task);
                                List_append(S->tasks, task);
                        } else {
                                memset(task, 0, sizeof *(task));
                        }
                        Str_copy(task->name, name, 20);
                        task->scheduler = S;
                }
        }
        END_LOCK;
        return task;
}


/* ------------------------------------------------------------------ Task */


void Task_once(Task_T t, double offset) {
        assert(t);
        assert(t->type == Task_None || t->type == Task_Once);
        t->type = Task_Once;
        t->offset = offset;
}


void Task_periodic(Task_T t, double offset, double interval) {
        assert(t);
        assert(interval > 0);
        assert(t->type == Task_None || t->type == Task_Periodic);
        t->type = Task_Periodic;
        t->offset = offset;
        t->interval = interval;
}


void Task_at(Task_T t, time_t time) {
        assert(t);
        assert(t->type == Task_None || t->type == Task_At);
        t->type = Task_At;
        t->offset = time;
}


const char *Task_getName(Task_T t) {
        assert(t);
        return t->name;
}


void Task_setData(Task_T t, void *data) {
        assert(t);
        t->data = data;
}


void *Task_getData(Task_T t) {
        assert(t);
        return t->data;
}


double Task_getOffset(Task_T t) {
        assert(t);
        return t->offset;
}


double Task_getInterval(Task_T t) {
        assert(t);
        return t->interval;
}


_Bool Task_isCanceled(Task_T t) {
        assert(t);
        return t->state == Task_Canceled;
}


void Task_setWorker(Task_T t, void (*worker)(Task_T t)) {
        assert(t);
        assert(worker);
        t->worker = worker;
}


time_t Task_lastRun(Task_T t) {
        assert(t);
        return (time_t)t->executed;
}


time_t Task_nextRun(Task_T t) {
        assert(t);
        if (t->type == Task_Once)
                return ev_is_active(&(t->ev.t)) ? (time_t)(ev_now(t->scheduler->loop) + ev_timer_remaining(t->scheduler->loop, &(t->ev.t))) : 0;
        else if (t->type == Task_Periodic || t->type == Task_At)
                return ev_is_active(&(t->ev.p)) ? (time_t)ev_periodic_at(&(t->ev.p)) : 0;
        else
                return 0;
}


/* ---------------------------------------------------------- Task Methods */


void Task_start(Task_T t) {
        assert(t);
        assert(t->isavailable == false);
        assert(t->worker);
        assert(t->type != Task_None);
        assert(t->state == Task_Initial);
        LOCK(t->scheduler->lock)
        {
                if (! t->scheduler->stopped) {
                        if (t->type == Task_Once) {
                                ev_now_update(t->scheduler->loop);
                                ev_timer_init(&(t->ev.t), _timer_cb, t->offset, 0);
                                ev_timer_start(t->scheduler->loop, &(t->ev.t));
                        } else {
                                ev_periodic_init(&(t->ev.p), _periodic_cb, t->offset, (t->type == Task_At) ? 0 : t->interval, NULL);
                                ev_periodic_start(t->scheduler->loop, &(t->ev.p));
                        }
                        t->state = Task_Started;
                        ev_async_send(t->scheduler->loop, &t->scheduler->loop_notify);
                }
        }
        END_LOCK;
}


void Task_cancel(Task_T t) {
        assert(t);
        assert(t->state != Task_Canceled);
        assert(t->isavailable == false);
        LOCK(t->scheduler->lock)
        {
                if (t->type == Task_Once)
                        ev_timer_stop(t->scheduler->loop, &(t->ev.t));
                else
                        ev_periodic_stop(t->scheduler->loop, &(t->ev.p));
                t->isavailable = true;
                t->state = Task_Canceled;
                ev_async_send(t->scheduler->loop, &t->scheduler->loop_notify);
        }
        END_LOCK;
}


void Task_restart(Task_T t) {
        assert(t);
        assert(t->isavailable == false);
        assert(t->worker);
        assert(t->state == Task_Started || t->state == Task_Limbo);
        LOCK(t->scheduler->lock)
        {
                if (! t->scheduler->stopped) {
                        ev_now_update(t->scheduler->loop);
                        switch (t->type) {
                                case Task_Once:
                                        t->ev.t.repeat = t->offset;
                                        ev_timer_again(t->scheduler->loop, &(t->ev.t));
                                        break;
                                case Task_Periodic:
                                        t->ev.p.interval = t->interval;
                                        // Fall-through
                                case Task_At:
                                        t->ev.p.offset = t->offset;
                                        ev_periodic_again(t->scheduler->loop, &(t->ev.p));
                                        break;
                                default:
                                        break;
                        }
                        t->state = Task_Started;
                        ev_async_send(t->scheduler->loop, &t->scheduler->loop_notify);
                }
        }
        END_LOCK;
}

