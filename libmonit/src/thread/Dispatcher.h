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


#ifndef DISPATCHER_INCLUDED
#define DISPATCHER_INCLUDED


/**
 * <b>Dispatcher</b> is a thread-safe worker pool queue manager which 
 * dispatch work to one or more threads. The <code>engine</code> method,
 * added at creation time, process data in its own thread of execution. 
 * 
 * <i>This class is thread-safe</i>
 * 
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#define T Dispatcher_T
typedef struct T *T;


/**
 * Create a new Dispatcher object
 * @param threads The maximum number of threads that should be used to
 * process the queue
 * @param timeout  The number of seconds a processor thread will wait for 
 * more work before timeout. The Dispatcher increase and reduce the
 * number of processor threads available depending on the work load.
 * @param engine The method for processing data passed to this queue
 * @return A new Dispatcher object or NULL if an error occured
 * @exception AssertException if initializing failed
 */
T Dispatcher_new(int threads, int timeout, void (*engine)(void *data));


/**
 * Destroy a Dispatcher object 
 * @param D A Dispatcher object reference
 */
void Dispatcher_free(T *D);


/**
 * Add new data to be processed to the Dispatcher's internal queue
 * @param D A Dispatcher object
 * @param data The data to be processed
 * @return true if data was added to the queue otherwise false.
 */
bool Dispatcher_add(T D, void *data);


#undef T
#endif
