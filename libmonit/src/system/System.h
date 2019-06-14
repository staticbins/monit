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


#ifndef SYSTEM_INCLUDED
#define SYSTEM_INCLUDED


/**
 * System routines
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/**
 * Returns a String describing the last system error
 * @return The last error message
 */
const char *System_getLastError(void);


/**
 * Returns a String describing the error code
 * @param error error code to lookup
 * @return The error string for the given code
 */
const char *System_getError(int error);


/**
 * Prints the given error message to <code>stderr</code> and 
 * <code>abort(3)</code> the application. If an AbortHandler callback 
 * function is defined for the library, this function is called instead.
 * @param e A formated (printf-style) message string
 */
void System_abort(const char *e, ...) __attribute__((format (printf, 1, 2)));


/**
 * Prints the given error message to <code>stderr</code>. If an ErrorHandler
 * callback function is defined for the library, this function is called instead.
 * @param e A formated (printf-style) message string
 */
void System_error(const char *e, ...) __attribute__((format (printf, 1, 2)));


/**
 * Prints the given message to <code>stdout</code> if the <code>MonitDebug</code>
 * variable is set to true, otherwise this function does nothing.
 * @param e A formated (printf-style) message string
 */
void System_debug(const char *e, ...) __attribute__((format (printf, 1, 2)));


/**
 * Returns the number of available file descriptors for a process.
 * This method uses <code>sysconf</code> internally, but returns
 * a fixed size of <code>2^16</code> if the value is larger. 
 * @return A guarded number of available file descriptors for a process
 */
int System_fds(void);


/**
 * Returns the number of available CPU cores on the system.
 * @return Numbers of available CPU cores on the system
 */
int System_cpus(void);


/**
 * Initialize the buf of size nbytes with random data.
 * @param buf The target buffer
 * @param nbytes The target buffer size in bytes
 * @return true on success, otherwise false
 */
bool System_random(void *buf, size_t nbytes);


/**
 * Get a random number. The number is returned in the range
 * 0..<limit. I.e. from 0 upto limit - 1. E.g. to return random
 * 0 or 1 use; System_randomNumber(2). To return a random number
 * between 0 and max, use System_randomNumber(UINT64_MAX). It is
 * a checked runtime error for limit to be less than 2 and larger
 * than UINT64_MAX.
 * @param limit The upper boundary of the random number
 * @return a random number between 0 and limit - 1.
 */
uint64_t System_randomNumber(uint64_t limit);


#endif
