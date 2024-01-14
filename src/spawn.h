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
        /// Optional: Set to true if spawn should detach, i.e. fire-and-forget
        /// once the program has called exec. Otherwise if false (the default)
        /// spawn will cache the Process_T object so the Process can be 
        /// inspected later
        bool detach;
        /// Optional: The event associated with the call. Used to set
        /// environment description
        Event_T E;
        /// Optional: Write any error to this buffer. If not set, the
        /// caller is expected to use errno to report the error
        char *err;
        // Optional: Required: if err is non-null
        int errlen;
} *spawn_args_t;


/// Create a new process from the command given in args.
/// If the detach property is false (the default) the Process_T
/// object created is cached in the global ProcessTable and can be
/// obtained using the returned pid
/// @param args Arguments given to spawn with information on how
/// to create the process
/// @return If creating the process failed, -1 is returned
/// and errno set to indicate the error that occured. On success
/// the process identification number (pid) of the new process
/// is returned
pid_t spawn(spawn_args_t args);


#endif /* spawn_h */
