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

#ifndef SPAWN_INCLUDED
#define SPAWN_INCLUDED

typedef struct spawn_args_t {
        /// Required: The Service_T object that request the new process
        Service_T S;
        /// Required: The command_t object containing the command to execute
        command_t cmd;
        /// Optional: The event associated with the Servvice. Used to set
        /// environment description
        Event_T E;
        /// Optional: Write any error to this buffer. If not set, the
        /// caller is expected to use errno to report the error
        char *err;
        // Optional: Required: if err is non-null
        int errlen;
} *spawn_args_t;


/// Create Service related processes' such as those given in a 'check process'
/// start, stop and restart statement or by any associated 'exec' statements.
/// The Process created from the 'start' program is special as it represents
/// the Service and the pid saved in a Service's pid-file. This Process is
/// cached in the global ProcessTable so the Service can retrieve and inspect
/// it's own Process later. All other Processes' created by this method are
/// created detached and not cached.
/// @param args A struct with information on how to create the process.
/// @return If creating the process failed, -1 is returned and errno set to
/// indicate the error that occured. On success the process identification
/// number (pid) of the new process is returned. 
pid_t spawn(spawn_args_t args);


#endif /* spawn_h */
