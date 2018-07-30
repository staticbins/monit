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


/* ----------------------------------------------------------------- Private */


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


static void _readDataFromSocket(Socket_T socket, char *data, int *wantBytes, int *haveBytes) {
        do {
                int n = Socket_read(socket, data + *haveBytes, *wantBytes);
                if (n <= 0) {
                        THROW(ProtocolException, "HTTP error: Receiving data -- %s", STRERROR);
                }
                (*haveBytes) += n;
                (*wantBytes) -= n;
        } while (*wantBytes > 0);
}


static void _checkContent(const char *data, Request_T R) {
        boolean_t rv = false;
        char error[STRLEN];
        int regex_return = regexec(R->regex, data, 0, NULL, 0);
        switch (R->operator) {
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


static void _checkChecksum(const char *data, int length, char *expectedChecksum, Hash_Type hashType) {
        MD_T hash;
        int keyLength = 0;
        switch (hashType) {
                case Hash_Md5:
                        {
                                md5_context_t ctx_md5;
                                md5_init(&ctx_md5);
                                md5_append(&ctx_md5, (const md5_byte_t *)data, length);
                                md5_finish(&ctx_md5, (md5_byte_t *)hash);
                                keyLength = 16; /* Raw key bytes not string chars! */
                        }
                        break;
                case Hash_Sha1:
                        {
                                sha1_context_t ctx_sha1;
                                sha1_init(&ctx_sha1);
                                sha1_append(&ctx_sha1, (md5_byte_t *)data, length);
                                sha1_finish(&ctx_sha1, (md5_byte_t *)hash);
                                keyLength = 20; /* Raw key bytes not string chars! */
                        }
                        break;
                default:
                        THROW(ProtocolException, "HTTP checksum error: Unknown hash type");
        }
        MD_T result;
        if (strncasecmp(Util_digest2Bytes((unsigned char *)hash, keyLength, result), expectedChecksum, keyLength * 2) != 0)
                THROW(ProtocolException, "HTTP checksum error: Document checksum mismatch");
        DEBUG("HTTP: Succeeded testing document checksum\n");
}


static void _checkBody(Port_T P, const char *body, int contentLength) {
        if (P->url_request && P->url_request->regex)
                _checkContent(body, P->url_request);
        if (P->parameters.http.checksum)
                _checkChecksum(body, contentLength, P->parameters.http.checksum, P->parameters.http.hashtype);
}


static void _processBodyChunked(Socket_T socket, Port_T P, int *contentLength) {
        int wantBytes = 0;
        int haveBytes = 0;
        volatile char *data = NULL;
        TRY
        {
                while ((wantBytes = _getChunkSize(socket)) && haveBytes < Run.limits.httpContentBuffer) {
                        if (haveBytes + wantBytes > Run.limits.httpContentBuffer) {
                                DEBUG("HTTP: content buffer limit exceeded -- limiting the data to %d\n", Run.limits.httpContentBuffer);
                                wantBytes = Run.limits.httpContentBuffer - haveBytes;
                        } else {
                                wantBytes += 2; // Read CRLF terminator too
                        }
                        if (data) {
                                data = realloc((void *)data, haveBytes + wantBytes);
                        } else {
                                data = CALLOC(1, wantBytes);
                        }
                        _readDataFromSocket(socket, (void *)data, &wantBytes, &haveBytes);
                        // Shave the CRLF terminator off the data
                        haveBytes -= 2;
                        data[haveBytes] = 0;
                }
                _checkBody(P, (void *)data, haveBytes);
        }
        FINALLY
        {
                free((void *)data);
        }
        END_TRY;
}


static void _processBodyContentLength(Socket_T socket, Port_T P, int *contentLength) {
        if (*contentLength < 0) {
                THROW(ProtocolException, "HTTP error: Missing Content-Length header");
        } else if (*contentLength == 0) {
                THROW(ProtocolException, "HTTP error: No content returned from server");
        } else if (*contentLength > Run.limits.httpContentBuffer) {
                DEBUG("HTTP: content buffer limit exceeded -- limiting the data to %d\n", Run.limits.httpContentBuffer);
                *contentLength = Run.limits.httpContentBuffer;
        }
        int haveBytes = 0;
        int wantBytes = *contentLength;
        char *data = CALLOC(1, *contentLength + 1);
        TRY
        {
                _readDataFromSocket(socket, data, &wantBytes, &haveBytes);
                if (haveBytes != *contentLength) {
                        THROW(ProtocolException, "HTTP error: Content too small -- the server announced %d bytes but just %d bytes were received", *contentLength, haveBytes);
                }
                _checkBody(P, data, haveBytes);
        }
        FINALLY
        {
                FREE(data);
        }
        END_TRY;
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


static void _processHeaders(Socket_T socket, Port_T P, void (**processBody)(Socket_T socket, Port_T P, int *contentLength), int *contentLength) {
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
        void (*processBody)(Socket_T socket, Port_T P, int *contentLength) = NULL;

        _processStatus(socket, P);
        _processHeaders(socket, P, &processBody, &contentLength);
        if ((P->url_request && P->url_request->regex) || P->parameters.http.checksum) {
                if (processBody) {
                        processBody(socket, P, &contentLength);
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

