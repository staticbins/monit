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
        if (strncasecmp(Util_digest2Bytes(Checksum_finish(context), keyLength, hashString), checksum, keyLength * 2) != 0)
                THROW(AssertException, "Checksum error: %s mismatch (expected %s got %s)", checksumnames[context->type], checksum, hashString);
}

