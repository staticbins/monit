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


#include "Config.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#include "Str.h"
#include "io/File.h"
#include "system/System.h"


/**
 * Implementation of the System Facade for Unix Systems.
 *
 * @author https://tildeslash.com
 * @see https://mmonit.com
 * @file
 */


/* ----------------------------------------------------------- Definitions */


extern void(*_abortHandler)(const char *error, va_list ap);
extern void(*_errorHandler)(const char *error, va_list ap);
extern void(*_debugHandler)(const char *info, va_list ap);


/* ---------------------------------------------------------------- Public */


const char *System_lastError(void) {
        return strerror(errno);
}


const char *System_getError(int error) {
        return strerror(error);
}


void System_abort(const char *e, ...) {
        va_list ap;
        va_start(ap, e);
        if (_abortHandler) 
                _abortHandler(e, ap);
        else {
                vfprintf(stderr, e, ap);
                abort();
        }
        va_end(ap);
}


void System_error(const char *e, ...) {
        va_list ap;
        va_start(ap, e);
        if (_errorHandler)
                _errorHandler(e, ap);
        else
                vfprintf(stderr, e, ap);
        va_end(ap);
}


void System_debug(const char *d, ...) {
        if (_debugHandler) {
                va_list ap;
                va_start(ap, d);
                _debugHandler(d, ap);
                va_end(ap);
        }
}


int System_descriptors(int guard) {
        int fileDescriptors = (int)sysconf(_SC_OPEN_MAX);
        if (fileDescriptors < 2)
                fileDescriptors = getdtablesize();
        assert(fileDescriptors > 2);
        if (guard > 0) {
                if (fileDescriptors > guard)
                        fileDescriptors = guard;
        }
        return fileDescriptors;
}

