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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "protocol.h"

// libmonit
#include "exceptions/IOException.h"
#include "exceptions/ProtocolException.h"


/* ----------------------------------------------------------- Definitions */


typedef struct {
        // header
        int32_t messageSize;     // total message size
        int32_t messageId;       // message id (set by server)
        int32_t responseToId;    // response to id (from the original request)
        int32_t operation;       // operation type
        // OP_REPLY
        int32_t flags;           // flags
        long long cursorId;      // cursor id
        int32_t cursorStart;     // cursor start
        int32_t returned;        // returned documents count
        int32_t documentLength;  // document length
        unsigned char *response; // BSON encoded response object
} op_reply_t; /* Keep position, don't memory pack! */


/* --------------------------------------------------------------- Private */


static unsigned int B4(unsigned char *b) {
        unsigned int x;
        *(((char *)&x) + 0) = b[3];
        *(((char *)&x) + 1) = b[2];
        *(((char *)&x) + 2) = b[1];
        *(((char *)&x) + 3) = b[0];
        return ntohl(x);
}


static void _ping(Socket_T socket) {
        unsigned char ping[68] = {
                // Message header
                0x44, 0x00, 0x00, 0x00,                                           // total message size (68 bytes)
                0x01, 0x00, 0x00, 0x00,                                           // message id (1)
                0x00, 0x00, 0x00, 0x00,                                           // response to id (0)
                0xd4, 0x07, 0x00, 0x00,                                           // operation type (OP_QUERY = 2004)
                // Query
                0x00, 0x00, 0x00, 0x00,                                           // flags
                0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // db.collection C-string ("admin.$cmd")
                0x00, 0x00, 0x00, 0x00,                                           // number of documents to skip
                0xff, 0xff, 0xff, 0xff,                                           // number of documents to return (-1)
                // BSON encoded document
                0x1d, 0x00, 0x00, 0x00,                                           // total document length (29 bytes)
                // ismaster (executes the legacy topology discovery command)
                0x10,                                                             // element type (int32 = 0x10)
                0x69, 0x73, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,             // element name C-string ("ismaster")
                0x01, 0x00, 0x00, 0x00,                                           // element value (1)
                // helloOk (indicates support for the newer hello command)
                0x08,                                                             // element type (bool = 0x08)
                0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x4f, 0x6b, 0x00,                   // element name C-string ("helloOk")
                0x01,                                                             // element value (true = 1)
                0x00                                                              // BSON document terminal
        };
        if (Socket_write(socket, (unsigned char *)ping, sizeof(ping)) < 0)
                THROW(IOException, "MONGODB: ping command error -- %s", STRERROR);
}


static void _pong(Socket_T socket) {
        op_reply_t pong;
        unsigned char buf[STRLEN + 1];
        memset(&pong, 0, sizeof(op_reply_t));
        if (Socket_read(socket, buf, 16) < 16) // read the header
                THROW(IOException, "MONGODB: error receiving PING response -- %s", STRERROR);
        // Get message size (should have at minimum 51 bytes)
        pong.messageSize = B4(buf);
        if (pong.messageSize < 51)
                THROW(ProtocolException, "MONGODB: PING response error -- invalid size (%d)", pong.messageSize);
        // read message ID (ignore)
        pong.messageId = B4(buf + 4);
        // check response ID: should be 1 (hardcoded in _ping request above)
        pong.responseToId = B4(buf + 8);
        if (pong.responseToId != 1)
                THROW(ProtocolException, "MONGODB: PING response error -- unexpected response id (%d)", pong.responseToId);
        // check operation type: should be OP_REPLY == 0x1
        pong.operation = B4(buf + 12);
        if (pong.operation != 1)
                THROW(ProtocolException, "MONGODB: PING response error -- unexpected operation type (0x%x)", pong.operation);
        // read OP_REPLY
        int len = pong.messageSize - 16 > STRLEN ? STRLEN : pong.messageSize - 16; // Adjust message size for this buffer (minus 16 bytes of header - already read)
        if (Socket_read(socket, buf, len) != len)
                THROW(IOException, "MONGODB: error receiving OP_REPLY data -- %s", STRERROR);
        // read flags (ignore)
        pong.flags = B4(buf);
        // read cursor id (ignore)
        pong.cursorId = B4(buf + 4);
        // read cursor start (ignore)
        pong.cursorStart = B4(buf + 12);
        // read returned documents count
        pong.returned = B4(buf + 16);
        if (pong.returned < 1)
                THROW(ProtocolException, "MONGODB: PING response error -- unexpected documents count (%d)", pong.returned);
        // read document length (should have at minimum 11 bytes)
        pong.documentLength = B4(buf + 20);
        if (pong.documentLength < 11)
                THROW(ProtocolException, "MONGODB: PING response error -- unexpected documents length (%d)", pong.documentLength);
        // compare just the first element in the response (we expect helloOk=true)
        pong.response = buf + 24;
        unsigned char helloOk[10] = {
                0x08,                                           // element type (boolean = 0x8)
                0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x4f, 0x6b, 0x00, // element name C-string ("helloOk")
                0x01                                            // element value (true = 1)
        };
        if (memcmp(pong.response, helloOk, sizeof(helloOk)))
                THROW(ProtocolException, "MONGODB: PING response error -- invalid reply");
}


/* ---------------------------------------------------------------- Public */


/**
 * Simple mongoDB ping test.
 *
 *     1. send a {ping:1} request to "admin.$cmd"
 *     2. expect a {ok:1} response
 *
 * @see https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/ and https://bsonspec.org/spec.html
 *
 * @file
 */
void check_mongodb(Socket_T socket) {
        assert(socket);
        _ping(socket);
        _pong(socket);
}

