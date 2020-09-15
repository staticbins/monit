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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include "monit.h"
#include "md5.h"
#include "sha1.h"
#include "checksum.h"

// libmonit
#include "exceptions/AssertException.h"
#include "io/File.h"


#define T ChecksumContext_T


/* ------------------------------------------------------------------ Public */


void Checksum_init(T context, Hash_Type type) {
        ASSERT(context);
        switch (type) {
                case Hash_Md5:
                        md5_init(&(context->data.md5));
                        break;
                case Hash_Sha1:
                        sha1_init(&(context->data.sha1));
                        break;
                default:
                        THROW(AssertException, "Checksum error: Unknown hash type");
                        break;
        }
        context->type = type;
        context->finished = false;
}


unsigned char *Checksum_finish(T context) {
        ASSERT(context);
        if (! context->finished) {
                switch (context->type) {
                        case Hash_Md5:
                                md5_finish(&(context->data.md5), (md5_byte_t *)context->hash);
                                break;
                        case Hash_Sha1:
                                sha1_finish(&(context->data.sha1), (unsigned char *)context->hash);
                                break;
                        default:
                                THROW(AssertException, "Checksum error: Unknown hash type");
                                break;
                }
                context->finished = true;
        }
        return (unsigned char *)(context->hash);
}


void Checksum_append(T context, const char *input, int inputLength) {
        ASSERT(context);
        ASSERT(input);
        ASSERT(inputLength >= 0);
        ASSERT(context->finished == false);
        switch (context->type) {
                case Hash_Md5:
                        md5_append(&(context->data.md5), (const md5_byte_t *)input, inputLength);
                        break;
                case Hash_Sha1:
                        sha1_append(&(context->data.sha1), (const unsigned char *)input, inputLength);
                        break;
                default:
                        THROW(AssertException, "Checksum error: Unknown hash type");
                        break;
        }
}


void Checksum_verify(T context, const char *checksum) {
        ASSERT(context);
        ASSERT(checksum);
        // Compare with string
        int keyLength = 0; // Raw key bytes, not string chars
        switch (context->type) {
                case Hash_Md5:
                        keyLength = 16;
                        break;
                case Hash_Sha1:
                        keyLength = 20;
                        break;
                default:
                        THROW(AssertException, "Checksum error: Unknown hash type");
                        break;
        }
        MD_T hashString = {};
        if (strncasecmp(Checksum_digest2Bytes(Checksum_finish(context), keyLength, hashString), checksum, keyLength * 2) != 0)
                THROW(AssertException, "Checksum error: %s mismatch (expected %s got %s)", checksumnames[context->type], checksum, hashString);
}


char *Checksum_digest2Bytes(unsigned char *digest, int mdlen, MD_T result) {
        int i;
        unsigned char *tmp = (unsigned char*)result;
        static unsigned char hex[] = "0123456789abcdef";
        ASSERT(mdlen * 2 < MD_SIZE); // Overflow guard
        for (i = 0; i < mdlen; i++) {
                *tmp++ = hex[digest[i] >> 4];
                *tmp++ = hex[digest[i] & 0xf];
        }
        *tmp = '\0';
        return result;
}


bool Checksum_getStreamDigests(FILE *stream, void *sha1_resblock, void *md5_resblock) {
#define HASHBLOCKSIZE 4096
        md5_context_t ctx_md5;
        sha1_context_t ctx_sha1;
        unsigned char buffer[HASHBLOCKSIZE + 72];
        size_t sum;

        /* Initialize the computation contexts */
        if (md5_resblock)
                md5_init(&ctx_md5);
        if (sha1_resblock)
                sha1_init(&ctx_sha1);

        /* Iterate over full file contents */
        while (1)  {
                /* We read the file in blocks of HASHBLOCKSIZE bytes. One call of the computation function processes the whole buffer so that with the next round of the loop another block can be read */
                size_t n;
                sum = 0;

                /* Read block. Take care for partial reads */
                while (1) {
                        n = fread(buffer + sum, 1, HASHBLOCKSIZE - sum, stream);
                        sum += n;
                        if (sum == HASHBLOCKSIZE)
                                break;
                        if (n == 0) {
                                /* Check for the error flag IFF N == 0, so that we don't exit the loop after a partial read due to e.g., EAGAIN or EWOULDBLOCK */
                                if (ferror(stream))
                                        return false;
                                goto process_partial_block;
                        }

                        /* We've read at least one byte, so ignore errors. But always check for EOF, since feof may be true even though N > 0. Otherwise, we could end up calling fread after EOF */
                        if (feof(stream))
                                goto process_partial_block;
                }

                /* Process buffer with HASHBLOCKSIZE bytes. Note that HASHBLOCKSIZE % 64 == 0 */
                if (md5_resblock)
                        md5_append(&ctx_md5, (const md5_byte_t *)buffer, HASHBLOCKSIZE);
                if (sha1_resblock)
                        sha1_append(&ctx_sha1, buffer, HASHBLOCKSIZE);
        }

process_partial_block:
        /* Process any remaining bytes */
        if (sum > 0) {
                if (md5_resblock)
                        md5_append(&ctx_md5, (const md5_byte_t *)buffer, (int)sum);
                if (sha1_resblock)
                        sha1_append(&ctx_sha1, buffer, sum);
        }
        /* Construct result in desired memory */
        if (md5_resblock)
                md5_finish(&ctx_md5, md5_resblock);
        if (sha1_resblock)
                sha1_finish(&ctx_sha1, sha1_resblock);
        return true;
}


void Checksum_printHash(char *file) {
        MD_T hash;
        unsigned char sha1[STRLEN], md5[STRLEN];
        FILE *fhandle = NULL;

        if (! (fhandle = file ? fopen(file, "r") : stdin) || ! Checksum_getStreamDigests(fhandle, sha1, md5) || (file && fclose(fhandle))) {
                printf("%s: %s\n", file, STRERROR);
                exit(1);
        }
        printf("SHA1(%s) = %s\n", file ? file : "stdin", Checksum_digest2Bytes(sha1, 20, hash));
        printf("MD5(%s)  = %s\n", file ? file : "stdin", Checksum_digest2Bytes(md5, 16, hash));
}


bool Checksum_getChecksum(char *file, Hash_Type hashtype, char *buf, unsigned long bufsize) {
        int hashlength = 16;

        ASSERT(file);
        ASSERT(buf);
        ASSERT(bufsize >= sizeof(MD_T));

        switch (hashtype) {
                case Hash_Md5:
                        hashlength = 16;
                        break;
                case Hash_Sha1:
                        hashlength = 20;
                        break;
                default:
                        Log_error("checksum: invalid hash type: 0x%x\n", hashtype);
                        return false;
        }

        if (File_isFile(file)) {
                FILE *f = fopen(file, "r");
                if (f) {
                        bool fresult = false;
                        MD_T sum;

                        switch (hashtype) {
                                case Hash_Md5:
                                        fresult = Checksum_getStreamDigests(f, NULL, sum);
                                        break;
                                case Hash_Sha1:
                                        fresult = Checksum_getStreamDigests(f, sum, NULL);
                                        break;
                                default:
                                        break;
                        }

                        if (fclose(f))
                                Log_error("checksum: error closing file '%s' -- %s\n", file, STRERROR);

                        if (! fresult) {
                                Log_error("checksum: file %s stream error (0x%x)\n", file, fresult);
                                return false;
                        }

                        Checksum_digest2Bytes((unsigned char *)sum, hashlength, buf);
                        return true;

                } else
                        Log_error("checksum: failed to open file %s -- %s\n", file, STRERROR);
        } else
                Log_error("checksum: file %s is not regular file\n", file);
        return false;
}


void Checksum_hmacMD5(const unsigned char *data, int datalen, const unsigned char *key, int keylen, unsigned char *digest) {
        md5_context_t ctx;
        md5_init(&ctx);
        unsigned char k_ipad[65] = {};
        unsigned char k_opad[65] = {};
        unsigned char tk[16];
        int i;

        if (keylen > 64) {
                md5_context_t tctx;
                md5_init(&tctx);
                md5_append(&tctx, (const md5_byte_t *)key, keylen);
                md5_finish(&tctx, tk);
                key = tk;
                keylen = 16;
        }

        memcpy(k_ipad, key, keylen);
        memcpy(k_opad, key, keylen);

        for (i = 0; i < 64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }

        md5_init(&ctx);
        md5_append(&ctx, (const md5_byte_t *)k_ipad, 64);
        md5_append(&ctx, (const md5_byte_t *)data, datalen);
        md5_finish(&ctx, digest);

        md5_init(&ctx);
        md5_append(&ctx, (const md5_byte_t *)k_opad, 64);
        md5_append(&ctx, (const md5_byte_t *)digest, 16);
        md5_finish(&ctx, digest);
}

