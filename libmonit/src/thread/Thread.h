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


#ifndef THREAD_INCLUDED
#define THREAD_INCLUDED
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include "system/System.h"


/**
 * General purpose <b>Thread</b> abstractions. This interface  defines object
 * types and methods for handling threads, synchronization and semaphores. 
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/** @cond hidden */
#define __trapper(F) do { \
        int status = (F); if (! (status == 0 || status==ETIMEDOUT)) \
        THROW(AssertException, "%s -- %s", #F, System_getError(status)); \
} while (0)
/** @endcond */
/** @name Abstract Data Types */
//@{
/**
 * Thread object type
 * @hideinitializer
 */
#define Thread_T pthread_t
/**
 * Semaphore object type
 * @hideinitializer
 */
#define Sem_T   pthread_cond_t			  
/**
 * Mutex object type
 * @hideinitializer
 */
#define Mutex_T pthread_mutex_t
/**
 * Read/Write Lock object type
 * @hideinitializer
 */
#define Lock_T pthread_rwlock_t
/**
 * Thread Data object type
 * @hideinitializer
 */
#define ThreadData_T pthread_key_t
//@}
/** @name Thread methods */
//@{
/**
 * Create a new thread
 * @param thread The thread to create
 * @param threadFunc The thread routine to execute
 * @param threadArgs Arguments to <code>threadFunc</code>
 * @exception AssertException If thread creation failed
 * @hideinitializer
 */
#define Thread_create(thread, threadFunc, threadArgs) \
        __trapper(pthread_create(&thread, NULL, threadFunc, (void*)threadArgs))
/**
 * Returns the thread ID of the calling thread
 * @return The id of the calling thread
 * @hideinitializer
 */
#define Thread_self() pthread_self()
/**
 * Detach a thread
 * @param thread The thread to detach
 * @exception AssertException If detaching the thread failed
 * @hideinitializer
 */
#define Thread_detach(thread) __trapper(pthread_detach(thread))
/**
 * Cancel execution of a thread
 * @param thread The thread to cancel
 * @exception AssertException If thread cancellation failed
 * @hideinitializer
 */
#define Thread_cancel(thread) __trapper(pthread_cancel(thread))
/**
 * Wait for thread termination
 * @param thread The thread to wait for
 * @exception AssertException If thread join failed
 * @hideinitializer
 */
#define Thread_join(thread) __trapper(pthread_join(thread, NULL))
//@}
/** @name Semaphore methods */
//@{
/**
 * Initialize a new semaphore
 * @param sem The semaphore to initialize
 * @exception AssertException If initialization failed
 * @hideinitializer
 */
#define Sem_init(sem) __trapper(pthread_cond_init(&sem, NULL))
/**
 * Wait on a semaphore
 * @param sem The semaphore to wait on
 * @param mutex A mutex to unlock on wait
 * @exception AssertException If wait failed
 * @hideinitializer
 */
#define Sem_wait(sem, mutex) __trapper(pthread_cond_wait(&sem, &(mutex)))
/**
 * Unblock a thread waiting for a semaphore
 * @param sem The semaphore to signal
 * @exception AssertException If signal failed
 * @hideinitializer
 */
#define Sem_signal(sem) __trapper(pthread_cond_signal(&sem))
/**
 * Unblock all threads waiting for a semaphore
 * @param sem The semaphore to broadcast
 * @exception AssertException If broadcast failed
 * @hideinitializer
 */
#define Sem_broadcast(sem) __trapper(pthread_cond_broadcast(&sem))
/**
 * Destroy a semaphore
 * @param sem The semaphore to destroy
 * @exception AssertException If destroy failed
 * @hideinitializer
 */
#define Sem_destroy(sem) __trapper(pthread_cond_destroy(&sem))
/**
 * Wait on a semaphore for a specific amount of time. During the wait
 * the mutex is unlocked and reacquired afterwards
 * @param sem The semaphore to wait on
 * @param mutex A mutex to unlock on wait
 * @param time time to wait
 * @exception AssertException If the timed wait failed
 * @hideinitializer
 */
#define Sem_timeWait(sem, mutex, time) \
        __trapper(pthread_cond_timedwait(&sem, &(mutex), &time))
//@}
/** @name Mutex methods */
//@{
/**
 * Initialize a new mutex
 * @param mutex The mutex to initialize
 * @exception AssertException If initialization failed
 * @hideinitializer
 */
#define Mutex_init(mutex) __trapper(pthread_mutex_init(&(mutex), NULL))
/**
 * Destroy a the given mutex
 * @param mutex The mutex to destroy
 * @exception AssertException If destroy failed
 * @hideinitializer
 */
#define Mutex_destroy(mutex) __trapper(pthread_mutex_destroy(&(mutex)))
/**
 * Locks a mutex
 * @param mutex The mutex to lock
 * @exception AssertException If mutex lock failed
 * @hideinitializer
 */
#define Mutex_lock(mutex) __trapper(pthread_mutex_lock(&(mutex)))
/**
 * Unlocks a mutex
 * @param mutex The mutex to unlock
 * @exception AssertException If mutex unlock failed
 * @hideinitializer
 */
#define Mutex_unlock(mutex) __trapper(pthread_mutex_unlock(&(mutex)))
/**
 * Defines a block of code to execute after the given mutex is locked
 * @param mutex The mutex to lock
 * @hideinitializer
 */
#define LOCK(mutex) do { Mutex_T *_yymutex=&(mutex); int _yystatus=pthread_mutex_lock(_yymutex); assert(_yystatus==0);
/**
 * Ends a LOCK block
 * @hideinitializer
 */
#define END_LOCK _yystatus=pthread_mutex_unlock(_yymutex); assert(_yystatus==0); } while (0)
//@}
/** @name Read/Write Lock methods */
//@{
/**
 * Initialize a new read/write lock
 * @param lock The lock to initialize
 * @exception AssertException If initialization failed
 * @hideinitializer
 */
#define Lock_init(lock) __trapper(pthread_rwlock_init(&(lock), NULL))
/**
 * Destroy a read/write lock
 * @param lock The lock to destroy
 * @exception AssertException If destroy failed
 * @hideinitializer
 */
#define Lock_destroy(lock) __trapper(pthread_rwlock_destroy(&(lock)))
/**
 * Acquire a read/write lock for reading
 * @param lock A read/write lock
 * @exception AssertException If failed
 * @hideinitializer
 */
#define Lock_read(lock) __trapper(pthread_rwlock_rdlock(&(lock)))
/**
 * Acquire a read/write lock for writing
 * @param lock A read/write lock
 * @exception AssertException If failed
 * @hideinitializer
 */
#define Lock_write(lock) __trapper(pthread_rwlock_wrlock(&(lock)))
/**
 * Release a read/write lock
 * @param lock A read/write lock
 * @exception AssertException If failed
 * @hideinitializer
 */
#define Lock_unlock(lock) __trapper(pthread_rwlock_unlock(&(lock)))
/**
 * Defines a block of code to execute after the given read locked is acquired
 * @param lock The read lock
 * @hideinitializer
 */
#define RLOCK(lock) do { Lock_T *_yyrlock=&(lock); int _yystatus=pthread_rwlock_rdlock(_yyrlock); assert(_yystatus==0);
/**
 * Ends a RLOCK block
 * @hideinitializer
 */
#define END_RLOCK _yystatus=pthread_rwlock_unlock(_yyrlock); assert(_yystatus==0);} while (0)
/**
 * Defines a block of code to execute after the given write locked is acquired
 * @param lock The write lock
 * @hideinitializer
 */
#define WLOCK(lock) do { Lock_T *_yywlock=&(lock); int _yystatus=pthread_rwlock_wrlock(_yywlock); assert(_yystatus==0);
/**
 * Ends a RLOCK block
 * @hideinitializer
 */
#define END_WLOCK _yystatus=pthread_rwlock_unlock(_yywlock); assert(_yystatus==0); } while (0)
//@}
/** @name Thread data methods */
//@{
/**
 * Creates a thread-specific data key. 
 * @param key The ThreadData_T key to create
 * @exception AssertException If thread data creation failed
 * @hideinitializer
 */
#define ThreadData_create(key) __trapper(pthread_key_create(&(key), NULL))
/**
 * Sets a thread-specific data value. The key is of type ThreadData_T
 * @param key The ThreadData_T key to set a new value for
 * @param value The value for key
 * @exception AssertException If setting thread data failed
 * @hideinitializer
 */
#define ThreadData_set(key, value) __trapper(pthread_setspecific((key), (value)))
/**
 * Gets a thread-specific data value
 * @param key The ThreadData_T key
 * @return value of key or NULL of no value was set for the key
 * @hideinitializer
 */
#define ThreadData_get(key) pthread_getspecific((key))
//@}
/** @name Atomic Thread */
//@{
/**
 * An Atomic Thread object encapsulates a thread, along with synchronization
 * primitives and thread-specific data. It is designed to facilitate thread
 * creation, synchronization, and cleanup in a thread-safe manner.
 *
 * An Atomic Thread should be initialized using `Thread_initAtomicThread`. This
 * ensure that the synchronization primitives `sem` and `mutex` are initialized
 * before the thread is created and that the threads active state is false.
 *
 * Use `Thread_createAtomicDetached` or `Thread_createAtomic` to create the
 * thread. You can reuse the same AtomicThread_T variable to call these methods
 * to restart the thread if needed. Use `Thread_isAtomicThreadActive` to test
 * if the thread is active/running. Finally, use `Thread_cleanupAtomicThread`
 * to destroy the semaphore and mutex in a deterministic manner.
 * @hideinitializer
 */typedef struct {
        Sem_T sem;
        Mutex_T mutex;
        Thread_T value;
        _Atomic(bool) active;
        void *threadArgs;
        void *(*threadFunc)(void *threadArgs);
} AtomicThread_T;
//@}

// ------------------------------------------------------------- Public Methods

//<< Start filter-out

/**
 * Initialize Threads. This method should be called at program startup
 */
void Thread_init(void);

//>> End filter-out

/**
 * Create a new thread in a detached state
 * @param thread The thread to create
 * @param threadFunc The thread routine to execute
 * @param threadArgs Arguments to <code>threadFunc</code>
 * @exception AssertException If thread creation failed
 */
void Thread_createDetached(Thread_T *thread, void *(*threadFunc)(void *threadArgs), void *threadArgs);

// -------------------------------------------------------------- Atomic Thread

/**
 * Initialize an Atomic Thread object.
 * This function initializes the synchronization primitives (`sem` and `mutex`)
 * and sets the `active` flag to false. It must be called before creating the
 * thread using `Thread_createAtomic` or `Thread_createAtomicDetached`.
 * @param thread A pointer to the Atomic Thread object to initialize
 * @exception AssertException If `thread` is NULL
 */
void Thread_initAtomicThread(AtomicThread_T *thread);

/**
 * Create a new Atomic Thread
 * @param thread The Atomic thread to create
 * @param threadFunc The thread routine to execute
 * @param threadArgs Arguments to <code>threadFunc</code>
 * @exception AssertException If thread creation failed or if the thread has
 * not been initialized using `Thread_initAtomicThread`
 */
void Thread_createAtomicThread(AtomicThread_T *thread, void *(*threadFunc)(void *threadArgs), void *threadArgs);

/**
 * Create a new Atomic Thread in a detached state
 * @param thread The Atomic thread to create
 * @param threadFunc The thread routine to execute
 * @param threadArgs Arguments to <code>threadFunc</code>
 * @exception AssertException If thread creation failed or if the thread has
 * not been initialized using` Thread_initAtomicThread`
 */
void Thread_createAtomicThreadDetached(AtomicThread_T *thread, void *(*threadFunc)(void *threadArgs), void *threadArgs);

/**
 * Returns true if the Atomic Thread is active/running
 * @param thread An Atomic thread
 * @return True if thread is active, otherwise false
 */
bool Thread_isAtomicThreadActive(AtomicThread_T *thread);

/**
 * Destroy the synchronization primitives in the Atomic Thread
 * @param thread An Atomic thread
 */
void Thread_cleanupAtomicThread(AtomicThread_T *thread);


#endif
