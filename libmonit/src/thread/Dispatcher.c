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
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

#include "List.h"
#include "Thread.h"
#include "system/System.h"
#include "Dispatcher.h"


/**
 * Implementation of the Dispatcher interface for Unix Systems. Based
 * on worker queue in "Programming with POSIX Threads" by Dave Butenhof
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ----------------------------------------------------------- Definitions */


#define T Dispatcher_T
struct T {
	int idle; 
	int quit;
	int counter;
        int timeout;
	List_T work;	
	int parallelism; 
	pthread_cond_t cv;
	pthread_attr_t attr;
	pthread_mutex_t mutex;
	void (*engine)(void *arg);
};


/* --------------------------------------------------------------- Private */


static int _ctor(T D) {
	int status = pthread_attr_init(&D->attr);
	if (status != 0)
		return status;
	status = pthread_attr_setdetachstate(&D->attr, PTHREAD_CREATE_DETACHED);
	if (status != 0) {
		pthread_attr_destroy(&D->attr);
		return status;
	}
	status = pthread_mutex_init(&D->mutex, NULL);
	if (status != 0) {
		pthread_attr_destroy(&D->attr);
		return status;
	}
	status = pthread_cond_init(&D->cv, NULL);
	if (status != 0) {
		pthread_mutex_destroy(&D->mutex);
		pthread_attr_destroy(&D->attr);
		return status;
	}
	return 0;
}


static int _dtor(T D) {
	int status, status1, status2;
	status = pthread_mutex_lock(&D->mutex);
	if (status != 0)
		return status;
	if (D->counter > 0) {
		D->quit = true;
		if (D->idle > 0) {
			status = pthread_cond_broadcast(&D->cv);
			if (status != 0) {
				pthread_mutex_unlock(&D->mutex);
				return status;
			}
		}
		while (D->counter > 0) {
			status = pthread_cond_wait(&D->cv, &D->mutex);
			if (status != 0) {
				pthread_mutex_unlock(&D->mutex);
				return status;
			}
		}
	}
	status = pthread_mutex_unlock(&D->mutex);
	if (status != 0)
		return status;
	status = pthread_mutex_destroy(&D->mutex);
        status1 = pthread_cond_destroy(&D->cv);
	status2 = pthread_attr_destroy(&D->attr);
	return (status ? status : (status1 ? status1 : status2));
}


static void *_server(void *arg) {
	T D = arg;
	bool timedout = 0;
        struct timeval tv;
	struct timespec timeout = {};
	int status = pthread_mutex_lock(&D->mutex);
	if (status != 0) {
                ERROR("Dispatcher: Acquiring lock error -- %s\n", System_getError(status));
		return NULL;
        }
	while (1) {
		timedout = false;
		while ((D->work->length == 0) && !D->quit) {
                        gettimeofday(&tv, NULL);
                        timeout.tv_sec = tv.tv_sec + D->timeout;
			D->idle++;
			status = pthread_cond_timedwait(&D->cv, &D->mutex, &timeout);
			D->idle--;
			if (status == ETIMEDOUT) {
				timedout = true;
				break;
			} else if (status != 0) {
				D->counter--;
				status = pthread_mutex_unlock(&D->mutex);
                                if (status != 0)
                                        ERROR("Dispatcher: Release lock error -- %s\n", System_getError(status));
				return NULL;
			}
		}
		if (D->work->length > 0) {
			void *work = List_pop(D->work);
                        status = pthread_mutex_unlock(&D->mutex);
                        if (status != 0) {
                                List_append(D->work, work);
                                ERROR("Dispatcher: Release lock error -- %s\n", System_getError(status));
                                return NULL;
                        }
			D->engine(work);
			if (pthread_mutex_lock(&D->mutex) != 0)
                                return NULL;
		}
		if ((D->work->length == 0) && D->quit) {
			D->counter--;
			if (D->counter == 0)
				pthread_cond_broadcast(&D->cv);
			pthread_mutex_unlock(&D->mutex);
			return NULL;
		}
		if ((D->work->length == 0) && timedout) {
			D->counter--;
			break;
		}
	}
	pthread_mutex_unlock(&D->mutex);
	return NULL;
}


/* ---------------------------------------------------------------- Public */


T Dispatcher_new(int threads, int timeout, void (*engine)(void *data)) {
	T D;
	assert(engine);
	assert(threads>0);
	NEW(D);
	D->idle = 0;
	D->quit = 0;
	D->counter = 0; 
	D->engine = engine;
        D->timeout = timeout;
	D->work = List_new();
	D->parallelism = threads;
	int status = _ctor(D);
	if (status != 0) {
                Dispatcher_free(&D);
		THROW(AssertException, "Dispatcher: Error initializing -- %s", System_getError(status));
	}
	return D;
}


void Dispatcher_free(T *D) {
	assert(D && *D);
	int status = _dtor((*D));
	if (status != 0) {
		ERROR("Dispatcher: Error finalizing -- %s", System_getError(status));
	}
        List_free(&(*D)->work);
	FREE(*D);
}


bool Dispatcher_add(T D, void *data) {
	assert(D);
	assert(data);
	int status = pthread_mutex_lock(&D->mutex);
	if (status != 0) {
                ERROR("Dispatcher: Acquiring lock error -- %s\n", System_getError(status)); 
		return false;
        }
	List_append(D->work, data);
	if (D->idle >= D->work->length) {
		status = pthread_cond_signal(&D->cv);
		if (status != 0)
                        ERROR("Dispatcher: Condition signal error -- %s\n", System_getError(status));
	} else if (D->counter < D->parallelism) {
                pthread_t id;
		status = pthread_create(&id, &D->attr, _server, D);
		if (status != 0)
                        ERROR("Dispatcher: Error creating new dispatcher thread -- %s\n", System_getError(status));
		else
                        D->counter++;
	}
	pthread_mutex_unlock(&D->mutex);
	return true;
}
