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


#ifndef MONIT_VALIDATE_H
#define MONIT_VALIDATE_H

/**
 * The validate function transit the service_state of each service.
 *
 * State           -> Next Possible States
 * -------------------------------------------------
 * Idle            -> Starting, Started, Unmonitored
 * Starting        -> Started, Error
 * Started         -> Check, Error, Stopping, Restarting
 * Restarting      -> Started, Error
 * Stopping        -> Stopped, Error
 * Stopped         -> Starting, Unmonitored
 * Error           -> Starting, Started, Stopping, Stopped
 * Check           -> Started, Error
 * Unmonitored     -> Stopped, Started
 *
 * STATES:
 *
 * Idle: The initial state of a service before it has been monitored or assigned
 * any other state. It's a starting point for service lifecycle management.
 *
 * Starting: Indicates that a service is in the process of starting. This
 * involves the execution of the service's start command.
 *
 * Started: Denotes that a service is running and operational. The service may
 * transition to this state from Starting or Check if it's deemed healthy.
 *
 * Restarting: A distinct state for services that are undergoing a restart
 * operation, which may be performed via a dedicated restart command if
 * available. This state reflects the special handling of restart procedures.
 *
 * Stopping: Represents the phase where a service is being stopped, following
 * the invocation of the service's stop command.
 *
 * Stopped: Indicates that a service has been successfully stopped and is no
 * longer running. It can be a precursor to a service being started again or
 * become unmonitored.
 *
 * Error: Reflects an error condition encountered by a service. This state can
 * result from failures in starting, stopping, restarting, or during runtime
 * checks. Services in this state require intervention and automatic recovery
 * actions.
 *
 * Check: A state indicating that a service is currently undergoing runtime
 * checks to verify its health, such as memory usage, CPU load, or other
 * metrics. This can be an intensive process and is managed separately in a
 * thread-pool.
 *
 * Unmonitored: Used for services that are temporarily exempt from monitoring.
 * Services can be configured to start in this state or transition to it under
 * certain conditions.
 *
 * @file
 */


int validate(void);
Check_State check_process(Service_T);
Check_State check_filesystem(Service_T);
Check_State check_file(Service_T);
Check_State check_directory(Service_T);
Check_State check_remote_host(Service_T);
Check_State check_system(Service_T);
Check_State check_fifo(Service_T);
Check_State check_program(Service_T);
Check_State check_net(Service_T);

#endif
