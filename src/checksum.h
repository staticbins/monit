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


/**
 * Convert a digest buffer to a char string
 * @param digest buffer containing a MD digest
 * @param mdlen digest length
 * @param result buffer to write the result to. Must be at least 41 bytes long.
 * @return pointer to result buffer
 */
char *Checksum_digest2Bytes(unsigned char *digest, int mdlen, MD_T result);


/**
 * Compute SHA1 and MD5 message digests simultaneously for bytes read
 * from STREAM (suitable for stdin, which is not always rewindable).
 * The resulting message digest numbers will be written into the first
 * bytes of resblock buffers.
 * @param stream The stream from where the digests are computed
 * @param sha_resblock The buffer to write the SHA1 result to or NULL to skip the SHA1
 * @param md5_resblock The buffer to write the MD5 result to or NULL to skip the MD5
 * @return false if failed, otherwise true
 */
bool Checksum_getStreamDigests(FILE *stream, void *sha_resblock, void *md5_resblock);


/**
 * Print MD5 and SHA1 hashes to standard output for given file or standard input
 * @param file The file for which the hashes will be printed or NULL for stdin
 */
void Checksum_printHash(char *file);


/**
 * Store the checksum of given file in supplied buffer
 * @param file The file for which to compute the checksum
 * @param hashtype The hash type (Hash_Md5 or Hash_Sha1)
 * @param buf The buffer where the result will be stored
 * @param bufsize The size of the buffer
 * @return false if failed, otherwise true
 */
bool Checksum_getChecksum(char *file, Hash_Type hashtype, char *buf, unsigned long bufsize);


/**
 * Get the HMAC-MD5 signature
 * @param data The data to sign
 * @param datalen The length of the data to sign
 * @param key The key used for the signature
 * @param keylen The length of the key
 * @param digest Buffer containing a signature. Must be at least 16 bytes long.
 */
void Checksum_hmacMD5(const unsigned char *data, int datalen, const unsigned char *key, int keylen, unsigned char *digest);


#undef T
#endif

