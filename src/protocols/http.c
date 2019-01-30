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

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "md5.h"
#include "sha1.h"
#include "base64.h"
#include "protocol.h"
#include "httpstatus.h"
#include "util/Str.h"

// libmonit
#include "exceptions/IOException.h"
#include "exceptions/ProtocolException.h"

/**
 *  A HTTP test.
 *
 *  We send the following request to the server:
 *  'GET / HTTP/1.1'             ... if request statement isn't defined
 *  'GET /custom/page  HTTP/1.1' ... if request statement is defined
 *  and check the server's status code.
 *
 *  If the statement defines hostname, it's used in the 'Host:' header otherwise a default (empty) Host header is set.
 *
 *  If the status code is >= 400, an error has occurred.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


#define BUFSIZE 4096


typedef union ChecksumContext_T {
        md5_context_t  md5;
        sha1_context_t sha1;
} *ChecksumContext_T;


/* ----------------------------------------------------------------- Private */


static void _contentVerify(Port_T P, const char *data) {
        if (P->url_request && P->url_request->regex) {
                boolean_t rv = false;
                char error[512];
                int regex_return = regexec(P->url_request->regex, data, 0, NULL, 0);
                switch (P->url_request->operator) {
                        case Operator_Equal:
                                if (regex_return == 0) {
                                        rv = true;
                                        DEBUG("HTTP: Regular expression matches\n");
                                } else {
                                        char errbuf[STRLEN];
                                        regerror(regex_return, NULL, errbuf, sizeof(errbuf));
                                        snprintf(error, sizeof(error), "Regular expression doesn't match: %s", errbuf);
                                }
                                break;
                        case Operator_NotEqual:
                                if (regex_return == 0) {
                                        snprintf(error, sizeof(error), "Regular expression matches");
                                } else {
                                        rv = true;
                                        DEBUG("HTTP: Regular expression doesn't match\n");
                                }
                                break;
                        default:
                                snprintf(error, sizeof(error), "Invalid content operator");
                                break;
                }
                if (! rv)
                        THROW(ProtocolException, "HTTP error: %s", error);
        }
}


static void _checksumInit(Port_T P, ChecksumContext_T context) {
        if (P->parameters.http.checksum) {
                switch (P->parameters.http.hashtype) {
                        case Hash_Md5:
                                md5_init(&(context->md5));
                                break;
                        case Hash_Sha1:
                                sha1_init(&(context->sha1));
                                break;
                        default:
                                THROW(ProtocolException, "HTTP checksum error: Unknown hash type");
                }
        }
}


static void _checksumFinish(Port_T P, ChecksumContext_T context, MD_T hash) {
        if (P->parameters.http.checksum) {
                switch (P->parameters.http.hashtype) {
                        case Hash_Md5:
                                md5_finish(&(context->md5), (md5_byte_t *)hash);
                                break;
                        case Hash_Sha1:
                                sha1_finish(&(context->sha1), (unsigned char *)hash);
                                break;
                        default:
                                THROW(ProtocolException, "HTTP checksum error: Unknown hash type");
                }
        }
}


static void _checksumAppend(Port_T P, ChecksumContext_T context, const char *input, int inputLength) {
        if (P->parameters.http.checksum) {
                switch (P->parameters.http.hashtype) {
                        case Hash_Md5:
                                md5_append(&(context->md5), (const md5_byte_t *)input, inputLength);
                                break;
                        case Hash_Sha1:
                                sha1_append(&(context->sha1), (const unsigned char *)input, inputLength);
                                break;
                        default:
                                THROW(ProtocolException, "HTTP checksum error: Unknown hash type");
                }
        }
}


static void _checksumVerify(Port_T P, MD_T hash) {
        if (P->parameters.http.checksum) {
                int keyLength = 0;
                switch (P->parameters.http.hashtype) {
                        case Hash_Md5:
                                keyLength = 16; /* Raw key bytes not string chars! */
                                break;
                        case Hash_Sha1:
                                keyLength = 20; /* Raw key bytes not string chars! */
                                break;
                        default:
                                THROW(ProtocolException, "HTTP checksum error: Unknown hash type");
                }
                MD_T hashString = {};
                if (strncasecmp(Util_digest2Bytes((unsigned char *)hash, keyLength, hashString), P->parameters.http.checksum, keyLength * 2) != 0)
                        THROW(ProtocolException, "HTTP checksum error: Data checksum mismatch (expected %s got %s)", P->parameters.http.checksum, hashString);
                DEBUG("HTTP: Succeeded testing data checksum\n");
        }
}


static boolean_t _hasHeader(List_T list, const char *name) {
        if (list) {
                for (list_t h = list->head; h; h = h->next) {
                        char *header = h->e;
                        if (Str_startsWith(header, name))
                                if (header[strlen(name)] == ':') // Ensure that name is not just a prefix
                                        return true;
                }
        }
        return false;
}


static unsigned _getChunkSize(Socket_T socket) {
        char buf[9];
        unsigned wantBytes = 0;
        if (! Socket_readLine(socket, buf, sizeof(buf))) {
                THROW(IOException, "HTTP error: failed to read chunk size -- %s", STRERROR);
        }
        if (sscanf(buf, "%x", &wantBytes) != 1) {
                THROW(ProtocolException, "HTTP error: invalid chunk size: %s", buf);
        }
        return wantBytes;
}


static int _readDataFromSocket(Port_T P, Socket_T socket, char *data, int wantBytes) {
        int readBytes = 0;
        do {
                int n = Socket_read(socket, data + readBytes, wantBytes - readBytes);
                if (n <= 0) {
                        THROW(ProtocolException, "HTTP error: Receiving data -- %s", STRERROR);
                }
                readBytes += n;
        } while (readBytes < wantBytes);
        if (readBytes != wantBytes) {
                THROW(ProtocolException, "HTTP error: Content too small -- the server announced %d bytes but just %d bytes were received", wantBytes, readBytes);
        }
        return readBytes;
}


static void _readData(Socket_T socket, Port_T P, volatile char **data, int wantBytes, int *haveBytes, ChecksumContext_T context) {
        if (P->url_request && P->url_request->regex) {
                // The content test is required => cache the whole body
                *data = realloc((void *)*data, *haveBytes + wantBytes + 1);
                *haveBytes += _readDataFromSocket(P, socket, (void *)*data + *haveBytes, wantBytes);
                _checksumAppend(P, context, (const char *)*data, wantBytes);
                *(*data + *haveBytes) = 0;
        } else {
                // No content check is required => use small buffer and compute the checksum on the fly
                *haveBytes = 0;
                for (int readBytes = (wantBytes < BUFSIZE) ? wantBytes : BUFSIZE; *haveBytes < wantBytes; readBytes = (wantBytes - *haveBytes) < BUFSIZE ? (wantBytes - *haveBytes) : BUFSIZE) {
                        _readDataFromSocket(P, socket, (void *)*data, readBytes);
                        _checksumAppend(P, context, (const char *)*data, readBytes);
                        *haveBytes += readBytes;
                }
        }
}


static void _processBodyChunked(Socket_T socket, Port_T P, volatile char **data, int *contentLength, ChecksumContext_T context) {
        char crlf[2] = {};
        int wantBytes = 0;
        int haveBytes = 0;
        while ((wantBytes = _getChunkSize(socket)) && haveBytes < Run.limits.httpContentBuffer) {
                if (haveBytes + wantBytes > Run.limits.httpContentBuffer) {
                        DEBUG("HTTP: content buffer limit exceeded -- limiting the data to %d\n", Run.limits.httpContentBuffer);
                        wantBytes = Run.limits.httpContentBuffer - haveBytes;
                }
                _readData(socket, P, data, wantBytes, &haveBytes, context);
                // Read the CRLF terminator
                _readDataFromSocket(P, socket, crlf, 2);
        }
}


static void _processBodyContentLength(Socket_T socket, Port_T P, volatile char **data, int *contentLength, ChecksumContext_T context) {
        int haveBytes = 0;
        if (*contentLength < 0) {
                THROW(ProtocolException, "HTTP error: Missing Content-Length header");
        } else if (*contentLength == 0) {
                THROW(ProtocolException, "HTTP error: No content returned from server");
        } else if (*contentLength > Run.limits.httpContentBuffer) {
                DEBUG("HTTP: content buffer limit exceeded -- limiting the data to %d\n", Run.limits.httpContentBuffer);
                *contentLength = Run.limits.httpContentBuffer;
        }
        _readData(socket, P, data, *contentLength, &haveBytes, context);
}


static void _processStatus(Socket_T socket, Port_T P) {
        int status;
        char buf[512] = {};

        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "HTTP: Error receiving data -- %s", STRERROR);
        Str_chomp(buf);
        if (! sscanf(buf, "%*s %d", &status))
                THROW(ProtocolException, "HTTP error: Cannot parse HTTP status in response: %s", buf);
        if (! Util_evalQExpression(P->parameters.http.operator, status, P->parameters.http.hasStatus ? P->parameters.http.status : 400))
                THROW(ProtocolException, "HTTP error: Server returned status %d", status);
}


static void _processHeaders(Socket_T socket, Port_T P, void (**processBody)(Socket_T socket, Port_T P, volatile char **data, int *contentLength, ChecksumContext_T context), int *contentLength) {
        char buf[512] = {};

        while (Socket_readLine(socket, buf, sizeof(buf))) {
                if ((buf[0] == '\r' && buf[1] == '\n') || (buf[0] == '\n'))
                        break;
                Str_chomp(buf);
                if (Str_startsWith(buf, "Content-Length")) {
                        if (! sscanf(buf, "%*s%*[: ]%d", contentLength))
                                THROW(ProtocolException, "HTTP error: Parsing Content-Length response header '%s'", buf);
                        if (*contentLength < 0)
                                THROW(ProtocolException, "HTTP error: Ilegal Content-Length response header '%s'", buf);
                        *processBody = _processBodyContentLength;
                } else if (Str_startsWith(buf, "Transfer-Encoding")) {
                        if (Str_sub(buf, "chunked")) {
                                *processBody = _processBodyChunked;
                        }
                }
        }
}


/**
 * Check that the server returns a valid HTTP response as well as checksum
 * or content regex if required
 * @param s A socket
 */
static void _checkResponse(Socket_T socket, Port_T P) {
        int contentLength = -1;
        void (*processBody)(Socket_T socket, Port_T P, volatile char **data, int *contentLength, ChecksumContext_T context) = NULL;

        _processStatus(socket, P);
        _processHeaders(socket, P, &processBody, &contentLength);
        if ((P->url_request && P->url_request->regex) || P->parameters.http.checksum) {
                if (processBody) {
                        MD_T hash = {};
                        volatile char *data = CALLOC(1, BUFSIZE);
                        union ChecksumContext_T context = {};
                        TRY
                        {
                                // Read data
                                _checksumInit(P, &context);
                                processBody(socket, P, &data, &contentLength, &context);
                                _checksumFinish(P, &context, hash);
                                // Perform tests
                                _checksumVerify(P, hash);
                                _contentVerify(P, (char *)data);
                        }
                        FINALLY
                        {
                                free((void *)data);
                        }
                        END_TRY;
                } else {
                        THROW(ProtocolException, "HTTP error: uknown transfer encoding");
                }
        }
}


static char *_getAuthHeader(Port_T P) {
        if (P->url_request) {
                URL_T U = P->url_request->url;
                if (U)
                        return Util_getBasicAuthHeader(U->user, U->password);
        }
        return Util_getBasicAuthHeader(P->parameters.http.username, P->parameters.http.password);
}


static void _sendRequest(Socket_T socket, Port_T P) {
        char *auth = _getAuthHeader(P);
        StringBuffer_T sb = StringBuffer_create(168);
        //FIXME: add decompression support to InputStream and switch here to it + set Accept-Encoding to gzip, so the server can send body compressed (if we test checksum/content)
        StringBuffer_append(sb,
                            "%s %s HTTP/1.1\r\n"
                            "%s",
                            httpmethod[P->parameters.http.method],
                            P->parameters.http.request ? P->parameters.http.request : "/",
                            auth ? auth : "");
        FREE(auth);
        // Set default header values unless defined
        if (! _hasHeader(P->parameters.http.headers, "Host"))
                StringBuffer_append(sb, "Host: %s\r\n", Util_getHTTPHostHeader(socket, (char[STRLEN]){}, STRLEN));
        if (! _hasHeader(P->parameters.http.headers, "User-Agent"))
                StringBuffer_append(sb, "User-Agent: Monit/%s\r\n", VERSION);
        if (! _hasHeader(P->parameters.http.headers, "Accept"))
                StringBuffer_append(sb, "Accept: */*\r\n");
        if (! _hasHeader(P->parameters.http.headers, "Accept-Encoding"))
                StringBuffer_append(sb, "Accept-Encoding: identity\r\n"); // We want no compression
        if (! _hasHeader(P->parameters.http.headers, "Connection"))
                StringBuffer_append(sb, "Connection: close\r\n");
        // Add headers if we have them
        if (P->parameters.http.headers) {
                for (list_t p = P->parameters.http.headers->head; p; p = p->next) {
                        char *header = p->e;
                        StringBuffer_append(sb, "%s\r\n", header);
                }
        }
        StringBuffer_append(sb, "\r\n");
        int send_status = Socket_write(socket, (void*)StringBuffer_toString(sb), StringBuffer_length(sb));
        StringBuffer_free(&sb);
        if (send_status < 0)
                THROW(IOException, "HTTP: error sending data -- %s", STRERROR);
}


/* ------------------------------------------------------------------ Public */


void check_http(Socket_T socket) {
        ASSERT(socket);

        Port_T P = Socket_getPort(socket);
        ASSERT(P);

        _sendRequest(socket, P);
        _checkResponse(socket, P);
}

