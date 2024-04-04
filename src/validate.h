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

int validate(void);
State_Type check_process(Service_T);
State_Type check_filesystem(Service_T);
State_Type check_file(Service_T);
State_Type check_directory(Service_T);
State_Type check_remote_host(Service_T);
State_Type check_system(Service_T);
State_Type check_fifo(Service_T);
State_Type check_program(Service_T);
State_Type check_net(Service_T);

#endif
