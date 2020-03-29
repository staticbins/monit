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


#ifndef CONVERT_INCLUDED
#define CONVERT_INCLUDED

/**
 * General purpose value units string <b>Convert</b> <b>class methods</b>.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/**
 * Convert the numeric bytes value to a string representation scaled to
 * human friendly storage unit [B, kB, MB, etc.].
 * @param bytes Byte value to convert
 * @param s A result buffer, must be large enough to hold 10 chars
 * @return A pointer to s
 */
char *Convert_bytes2str(double bytes, char s[static 10]);


/**
 * Convert the time in milliseconds to human friendlier unit (ms/s/m/h/d/y).
 * @param milli The time value in milliseconds to present
 * @param s A result buffer, must be large enough to hold 11 chars
 * @return A pointer to s
 */
char *Convert_time2str(double milli, char s[static 11]);


#endif
