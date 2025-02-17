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


#ifndef RANDOM_INCLUDED
#define RANDOM_INCLUDED


/**
 * Random routines
 *
 * @author https://www.tildeslash.com/
 * @see https://mmonit.com/
 * @file
 */


/**
 * Initialize the buf of size nbytes with random data.
 * @param buf The target buffer
 * @param nbtyes The target buffer size in bytes
 * @return true on success, otherwise false
 */
bool Random_bytes(void *buf, size_t nbytes);


/**
 * Get a random number
 * @return random number
 */
unsigned long long Random_number(void);


#endif /* Random_h */
