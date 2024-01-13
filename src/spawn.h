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
        Service_T S;    // Required
        command_t cmd;  // Required
        Event_T E;      // Optional -
        char *err;      // Optional - Write any error to err instead of Log
        int errlen;     // Required if err
} *spawn_args_t;


/// Create a new process from the command given in args.
/// The Process_T object created is cached in the global
/// ProcessTable and can be obtained using the returned pid
/// @param args Arguments given to spawn to create the process
/// @return If creating the process failed, -1 is returned
/// and errno set to indicate the error that occured. On success
/// the process identification number (pid) of the new process
/// is returned
pid_t spawn(spawn_args_t args);


#endif /* spawn_h */
