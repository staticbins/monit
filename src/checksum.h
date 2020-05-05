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


#ifndef MONIT_CHECKSUM_H
#define MONIT_CHECKSUM_H

#include "monit.h"


/**
 * This class implements the <b>checksum</b> processing.
 *
 * @file
 */


#define T ChecksumContext_T
typedef struct T {
        bool finished;
        Hash_Type type;
        MD_T      hash;
        union {
                md5_context_t  md5;
                sha1_context_t sha1;
        } data;
} *T;


/**
 * Initialize the checksum context
 * @param context The checksum context
 * @param type Type of hash to initialize
 * @exception AssertException if context is NULL or hash type not MD5 not SHA1
 */
void Checksum_init(T context, Hash_Type type);


/**
 * Finish the checksum and store the resut in the hash buffer
 * @param context The checksum context
 * @return hash
 * @exception AssertException if context or hash is NULL
 */
unsigned char *Checksum_finish(T context);


/**
 * Finish the checksum and store the resut in the hash buffer
 * @param context The checksum context
 * @param input The data to be checksummed
 * @param inputLength The length of data to be checksummed
 * @exception AssertException if context or input NULL
 */
void Checksum_append(T context, const char *input, int inputLength);


/**
 * Compare the checksum with a string
 * @param context The checksum context
 * @param checksum The checksum string to compare
 * @exception AssertException if context or checksum is NULL
 */
void Checksum_verify(T context, const char *checksum);


#undef T
#endif

