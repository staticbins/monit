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

#include "protocol.h"

// libmonit
#include "exceptions/IOException.h"
#include "exceptions/ProtocolException.h"


#define BYE "* BYE"


/**
 *  Check the server for greeting code '* OK' and then send LOGOUT and check for code '* BYE'
 *
 *  @file
 */
void check_imap(Socket_T socket) {
        char buf[512];
        int sequence = 1;
        Port_T port = Socket_getPort(socket);

        ASSERT(socket);

        // Read and check IMAP greeting
        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "IMAP: greeting read error -- %s", errno ? STRERROR : "no data");
        Str_chomp(buf);
        if (! Str_startsWith(buf, "* OK"))
                THROW(ProtocolException, "IMAP: invalid greeting -- %s", buf);

        if (port->family != Socket_Unix && port->target.net.ssl.options.flags == SSL_StartTLS) {
                // Send STARTTLS command
                if (Socket_print(socket, "%03d STARTTLS\r\n", sequence++) < 0)
                        THROW(IOException, "IMAP: STARTTLS command error -- %s", STRERROR);

                // Parse STARTTLS response
                if (! Socket_readLine(socket, buf, sizeof(buf)))
                        THROW(IOException, "IMAP: STARTTLS response read error -- %s", errno ? STRERROR : "no data");
                Str_chomp(buf);
                if (! Str_startsWith(buf, "001 OK"))
                        THROW(ProtocolException, "IMAP: invalid logout response: %s", buf);

                // Switch to TLS
                Socket_enableSsl(socket, &(Run.ssl), NULL);
        }

        // Send LOGOUT command
        if (Socket_print(socket, "%03d LOGOUT\r\n", sequence++) < 0)
                THROW(IOException, "IMAP: logout command error -- %s", STRERROR);

        // Check LOGOUT response
        if (! Socket_readLine(socket, buf, sizeof(buf)))
                THROW(IOException, "IMAP: logout response read error -- %s", errno ? STRERROR : "no data");
        Str_chomp(buf);
        if (strncasecmp(buf, BYE, strlen(BYE)) != 0)
                THROW(ProtocolException, "IMAP: invalid logout response: %s", buf);
}

