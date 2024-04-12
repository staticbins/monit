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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "monit.h"
#include "device.h"
#include "TextColor.h"
#include "TextBox.h"
#include "httpstatus.h"
#include "client.h"
#include "daemonize.h"

// libmonit
#include "exceptions/AssertException.h"
#include "exceptions/IOException.h"

/**
 *  The monit HTTP GUI client
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


static void _argument(StringBuffer_T data, const char *name, const char *value) {
        char *_value = Util_urlEncode(value, true);
        StringBuffer_append(data, "%s%s=%s", StringBuffer_length(data) ? "&" : "", name, _value);
        FREE(_value);
}


static char *_getBasicAuthHeader(void) {
        Auth_T auth = NULL;
        // Find the first cleartext credential for authorization
        for (Auth_T c = Run.httpd.credentials; c; c = c->next) {
                if (c->digesttype == Digest_Cleartext) {
                        if (! auth || auth->is_readonly) {
                                auth = c;
                        }
                }
        }
        if (auth)
                return Util_getBasicAuthHeader(auth->uname, auth->passwd);
        return NULL;
}


static void _parseHttpResponse(Socket_T S) {
        char buf[1024];
        if (! Socket_readLine(S, buf, sizeof(buf)))
                THROW(IOException, "Error receiving data -- %s", System_lastError());
        Str_chomp(buf);
        int status;
        if (! sscanf(buf, "%*s %d", &status))
                THROW(IOException, "Cannot parse status in response: %s", buf);
        if (status < 300 || status == SC_MOVED_TEMPORARILY) {
                // Skip HTTP headers
                while (Socket_readLine(S, buf, sizeof(buf))) {
                         if (! strncmp(buf, "\r\n", sizeof(buf)))
                                break;
                }
        } else {
                int content_length = 0;
                // Read HTTP headers
                while (Socket_readLine(S, buf, sizeof(buf))) {
                        if (! strncmp(buf, "\r\n", sizeof(buf)))
                                break;
                        if (Str_startsWith(buf, "Content-Length") && ! sscanf(buf, "%*s%*[: ]%d", &content_length))
                                THROW(IOException, "Invalid Content-Length header: %s", buf);
                }
                // Parse error response
                char *message = NULL;
                if (content_length > 0 && content_length < 1024 && Socket_readLine(S, buf, sizeof(buf))) {
                        char token[] = "</h2>";
                        message = strstr(buf, token);
                        if (message && strlen(message) > strlen(token)) {
                                message += strlen(token);
                                char *footer = NULL;
                                if ((footer = strstr(message, "<p>")) || (footer = strstr(message, "<hr>")))
                                        *footer = 0;
                        }
                }
                THROW(AssertException, "%s", message ? message : "cannot parse response");
        }
}


static void _send(Socket_T S, const char *request, StringBuffer_T data) {
        _argument(data, "format", "text");
        char *_auth = _getBasicAuthHeader();
        MD_T token;
        StringBuffer_append(data, "%ssecuritytoken=%s", StringBuffer_length(data) > 0 ? "&" : "", Util_getToken(token));
        int rv = Socket_print(S,
                "POST %s HTTP/1.0\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Cookie: securitytoken=%s\r\n"
                "Content-Length: %d\r\n"
                 "%s"
                 "\r\n"
                 "%s",
                request,
                token,
                StringBuffer_length(data),
                _auth ? _auth : "",
                StringBuffer_toString(data));
        FREE(_auth);
        if (rv < 0)
                THROW(IOException, "Monit: cannot send command to the monit daemon -- %s", System_lastError());
}


static void _receive(Socket_T S) {
        char buf[1024];
        _parseHttpResponse(S);
        bool strip = (Run.flags & Run_Batch || ! TextColor_support()) ? true : false;
        while (Socket_readLine(S, buf, sizeof(buf))) {
                if (strip)
                        TextColor_strip(TextBox_strip(buf));
                printf("%s", buf);
        }
}


static bool _client(const char *request, StringBuffer_T data) {
        volatile bool status = false;
        if (! exist_daemon()) {
                Log_error("Monit: the monit daemon is not running\n");
                return status;
        }
        Socket_T S = NULL;
        // Connect via http if enabled except if set readonly and a unix socket was configured not readonly
        if ((Run.httpd.flags & Httpd_Net) && !(Run.httpd.socket.net.readonly && (Run.httpd.flags & Httpd_Unix) && !Run.httpd.socket.unix.readonly)) {
                S = Socket_create(Run.httpd.socket.net.address ? Run.httpd.socket.net.address : "localhost", Run.httpd.socket.net.port, Socket_Tcp, Socket_Ip, &(Run.httpd.socket.net.ssl), Run.limits.networkTimeout);
        } else if (Run.httpd.flags & Httpd_Unix) {
                S = Socket_createUnix(Run.httpd.socket.unix.path, Socket_Tcp, Run.limits.networkTimeout);
        } else {
                Log_error("Monit: the monit HTTP interface is not enabled, please add the 'set httpd' statement and use the 'allow' option to allow monit to connect\n");
        }
        if (S) {
                TRY
                {
                        _send(S, request, data);
                        _receive(S);
                        status = true;
                }
                ELSE
                {
                        Log_error("%s\n", Exception_frame.message);
                }
                END_TRY;
                Socket_free(&S);
        }
        return status;
}


/* ------------------------------------------------------------------ Public */


bool HttpClient_action(const char *action, List_T services) {
        assert(services);
        assert(action);
        if (Util_getAction(action) == Action_Ignored) {
                Log_error("Invalid action %s\n", action);
                return false;
        }
        StringBuffer_T data = StringBuffer_create(64);
        _argument(data, "action", action);
        for (list_t s = services->head; s; s = s->next)
                _argument(data, "service", s->e);
        bool rv = _client("/_doaction", data);
        StringBuffer_free(&data);
        return rv;
}


bool HttpClient_report(const char *group, const char *type) {
        StringBuffer_T data = StringBuffer_create(64);
        if (STR_DEF(group))
                _argument(data, "group", group);
        if (STR_DEF(type))
                _argument(data, "type", type);
        bool rv = _client("/_report", data);
        StringBuffer_free(&data);
        return rv;
}


bool HttpClient_status(const char *group, const char *service) {
        StringBuffer_T data = StringBuffer_create(64);
        if (STR_DEF(service))
                _argument(data, "service", service);
        if (STR_DEF(group))
                _argument(data, "group", group);
        bool rv = _client("/_status", data);
        StringBuffer_free(&data);
        return rv;
}


bool HttpClient_summary(const char *group, const char *service) {
        StringBuffer_T data = StringBuffer_create(64);
        if (STR_DEF(service))
                _argument(data, "service", service);
        if (STR_DEF(group))
                _argument(data, "group", group);
        bool rv = _client("/_summary", data);
        StringBuffer_free(&data);
        return rv;
}

