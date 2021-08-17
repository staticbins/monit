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

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#include "protocol.h"
#include "md5.h"
#include "sha1.h"
#include "checksum.h"

// libmonit
#include "exceptions/IOException.h"
#include "exceptions/ProtocolException.h"


#define PGERROR(e) ((e) ? (e->value) : "N/A")


/* ----------------------------------------------------------- Definitions */


typedef enum {
        PostgreSQL_Init,
        PostgreSQL_Error,
        PostgreSQL_AuthenticationOk,
        PostgreSQL_AuthenticationNeeded,
        PostgreSQL_AuthenticationNeededUnknownType
} __attribute__((__packed__)) PostgreSQLState;


typedef enum {
        PostgreSQLPacket_Notification     = 'A',
        PostgreSQLPacket_CommandComplete  = 'C',
        PostgreSQLPacket_Error            = 'E',
        PostgreSQLPacket_CopyIn           = 'G',
        PostgreSQLPacket_CopyOut          = 'H',
        PostgreSQLPacket_EmptyQuery       = 'I',
        PostgreSQLPacket_Notice           = 'N',
        PostgreSQLPacket_Authentication   = 'R', //Note: used by the whole Authentication message family
        PostgreSQLPacket_FunctionCall     = 'V',
        PostgreSQLPacket_CopyBoth         = 'W',
        PostgreSQLPacket_Terminate        = 'X',
        PostgreSQLPacket_PasswordMessage  = 'p', //Note: also used for GSSResponse, SASLInitialResponse, SASLResponse
        PostgreSQLPacket_PortalSuspended  = 's'
} __attribute__((__packed__)) PostgreSQLPacket;


typedef enum {
        PostgreSQLError_SeverityLocalized = 'S',
        PostgreSQLError_SeverityNative    = 'V',
        PostgreSQLError_Code              = 'C',
        PostgreSQLError_Message           = 'M',
        PostgreSQLError_Detail            = 'D',
        PostgreSQLError_Hint              = 'H',
        PostgreSQLError_Position          = 'P',
        PostgreSQLError_PositionInternal  = 'p',
        PostgreSQLError_QueryInternal     = 'q',
        PostgreSQLError_Where             = 'W',
        PostgreSQLError_SchemaName        = 's',
        PostgreSQLError_TableName         = 't',
        PostgreSQLError_ColumnName        = 'c',
        PostgreSQLError_DataTypeName      = 'd',
        PostgreSQLError_ConstraintName    = 'n',
        PostgreSQLError_File              = 'F',
        PostgreSQLError_Line              = 'L',
        PostgreSQLError_Routine           = 'R'
} __attribute__((__packed__)) PostgreSQLError;


typedef enum {
        PostgreSQLAuthentication_Ok                = 0,
        PostgreSQLAuthentication_KerberosV5        = 2,
        PostgreSQLAuthentication_CleartextPassword = 3,
        PostgreSQLAuthentication_MD5Password       = 5,
        PostgreSQLAuthentication_SCMCredential     = 6,
        PostgreSQLAuthentication_GSS               = 7,
        PostgreSQLAuthentication_GSSContinue       = 8,
        PostgreSQLAuthentication_SSPI              = 9,
        PostgreSQLAuthentication_SASL              = 10,
        PostgreSQLAuthentication_SASLContinue      = 11,
        PostgreSQLAuthentication_SASLFinal         = 12
} PostgreSQLAuthentication;


// See StartupMessage at https://www.postgresql.org/docs/current/protocol-message-formats.html
typedef struct postgresql_startupmessage_t {
        uint32_t length;
        uint32_t protocol_major : 16;
        uint32_t protocol_minor : 16;
        char parameters[1024];
} __attribute__((__packed__)) *postgresql_startupmessage_t;


// See PasswordMessage at https://www.postgresql.org/docs/current/protocol-message-formats.html
typedef struct postgresql_passwordmessage_t {
        PostgreSQLPacket type;
        uint32_t length;
        char data[1024];
} __attribute__((__packed__)) *postgresql_passwordmessage_t;


// See Terminate at https://www.postgresql.org/docs/current/protocol-message-formats.html
typedef struct postgresql_terminatemessage_t {
        PostgreSQLPacket type;
        uint32_t length;
} __attribute__((__packed__)) *postgresql_terminatemessage_t;


// https://www.postgresql.org/docs/current/protocol-message-formats.html: generic part which is common to all valid responses
// Note: we must pack the structure to match the PostgreSQL binary protocol
typedef struct postgresql_response_header_t {
        PostgreSQLPacket type;
        uint32_t length;
} __attribute__((__packed__)) *postgresql_response_header_t;


typedef struct postgresql_error_t {
        PostgreSQLError type;
        char value[256];
} __attribute__((__packed__)) *postgresql_error_t;


typedef struct postgresql_response_authentication_header_t {
        uint32_t length;
} __attribute__((__packed__)) *postgresql_response_authentication_header_t;


typedef struct postgresql_response_authentication_t {
        PostgreSQLAuthentication type;
        union {
                struct {
                        char salt[4];
                } md5;
                struct {
                        char data[64];
                } generic;
        } data;
} __attribute__((__packed__)) *postgresql_response_authentication_t;


typedef struct postgresql_response_t {
        struct postgresql_response_header_t header;
        union {
                char                                        buffer[1024];
                struct postgresql_response_authentication_t authentication;
        } data;
} __attribute__((__packed__)) *postgresql_response_t;


typedef struct postgresql_t {
        PostgreSQLState state;
        Socket_T socket;
        Port_T port;
        struct {
                char salt[4];
                void (*callback)(struct postgresql_t *postgresql);
        } authentication;
} *postgresql_t;


/* ------------------------------------------------------ Request handlers */


// Compute MD5 hash of the concatenated string
void _getMd5Hash(const char *s1, int s1Length, const char *s2, int s2Length, MD_T result) {
        MD_T digest;
        md5_context_t ctx;
        
        md5_init(&ctx);
        md5_append(&ctx, (const md5_byte_t *)s1, s1Length);
        md5_append(&ctx, (const md5_byte_t *)s2, s2Length);
        md5_finish(&ctx, digest);
        Checksum_digest2Bytes((unsigned char *)digest, 16, result);
}


// Password message with MD5 hash of username and password with salt per following algorithm:
//   concat('md5', md5(concat(md5(concat(password, username)), random-salt)))
// See:
//   PasswordMessage           at https://www.postgresql.org/docs/current/protocol-message-formats.html
//   AuthenticationMD5Password at https://www.postgresql.org/docs/current/protocol-flow.html#id-1.10.5.7.3
static void _authenticateMd5(postgresql_t postgresql) {
        MD_T hash;
        struct postgresql_passwordmessage_t passwordMessage = {
                .type = PostgreSQLPacket_PasswordMessage
        };
        int length = sizeof(passwordMessage.length);
        const char *username = postgresql->port->parameters.postgresql.username ? postgresql->port->parameters.postgresql.username : "";
        const char *password = postgresql->port->parameters.postgresql.password ? postgresql->port->parameters.postgresql.password : "";

        // Compute the hash of username and password with salt
        _getMd5Hash(password, strlen(password), username, strlen(username), hash);
        _getMd5Hash(hash, 32, postgresql->authentication.salt, 4, hash);

        // Set the password message
        length += snprintf(passwordMessage.data, sizeof(passwordMessage.data), "md5%s", hash) + 1;

        // Set the message length
        passwordMessage.length = htonl(length);

        // Send the password message
        if (Socket_write(postgresql->socket, (unsigned char *)&passwordMessage, length + 1) != length + 1)
                THROW(IOException, "PGSQL: error sending clear text password message -- %s", STRERROR);
}


// See:
//   PasswordMessage                 at https://www.postgresql.org/docs/current/protocol-message-formats.html
//   AuthenticationCleartextPassword at https://www.postgresql.org/docs/current/protocol-flow.html#id-1.10.5.7.3
static void _authenticateClearPassword(postgresql_t postgresql) {
        int length = 0;
        struct postgresql_passwordmessage_t passwordMessage = {
                .type = PostgreSQLPacket_PasswordMessage
        };

        if (postgresql->port->parameters.postgresql.password) {
                length += sizeof(passwordMessage.length) + snprintf(passwordMessage.data, sizeof(passwordMessage.data), "%s", postgresql->port->parameters.postgresql.password) + 1;
        }
        passwordMessage.length = htonl(length);
        if (Socket_write(postgresql->socket, (unsigned char *)&passwordMessage, length + 1) != length + 1)
                THROW(IOException, "PGSQL: error sending clear text password message -- %s", STRERROR);
}


// See StartupMessage at https://www.postgresql.org/docs/current/protocol-message-formats.html
static void _requestStartup(postgresql_t postgresql) {
        int length = 0;
        struct postgresql_startupmessage_t startupMessage = {
                .protocol_major = htons(3),
                .protocol_minor = 0
        };

        // Username: this is the only required parameter
        length += snprintf(startupMessage.parameters + length, sizeof(startupMessage.parameters) - length, "user") + 1;
        if (postgresql->port->parameters.postgresql.username) {
                length += snprintf(startupMessage.parameters + length, sizeof(startupMessage.parameters) - length, "%s", postgresql->port->parameters.postgresql.username) + 1;
        } else {
                // No username set in the protocol, fallback to 'root' for backward compatibility
                length += snprintf(startupMessage.parameters + length, sizeof(startupMessage.parameters) - length, "root") + 1;
        }

        // Database: optional, defaults to username if not set
        if (postgresql->port->parameters.postgresql.database) {
                length += snprintf(startupMessage.parameters + length, sizeof(startupMessage.parameters) - length, "database") + 1;
                length += snprintf(startupMessage.parameters + length, sizeof(startupMessage.parameters) - length, "%s", postgresql->port->parameters.postgresql.database) + 1;
        } else if (! postgresql->port->parameters.postgresql.username) {
                // Backward compatibility: Monit < 5.29.0 did always set user=root and database=root. If the test doesn't specify user nor database, mimick Monit 5.29.0 behaviour
                length += snprintf(startupMessage.parameters + length, sizeof(startupMessage.parameters) - length, "database") + 1;
                length += snprintf(startupMessage.parameters + length, sizeof(startupMessage.parameters) - length, "root") + 1;
        }

        length += sizeof(startupMessage.length) + sizeof(uint32_t) + 1; // Add protocol length and the name/value pair NULL terminator
        startupMessage.length = htonl(length);

        if (Socket_write(postgresql->socket, (unsigned char *)&startupMessage, length) != length)
                THROW(IOException, "PGSQL: error sending startup message -- %s", STRERROR);
}


static void _requestTerminate(postgresql_t postgresql) {
        struct postgresql_terminatemessage_t terminateMessage = {
                .type = PostgreSQLPacket_Terminate,
                .length = htonl(4)
        };
        if (Socket_write(postgresql->socket, (unsigned char *)&terminateMessage, sizeof(struct postgresql_terminatemessage_t)) != sizeof(struct postgresql_terminatemessage_t))
                THROW(IOException, "PGSQL: error sending terminate message -- %s", STRERROR);
}


/* ----------------------------------------------------- Response handlers */


static void _handleError(postgresql_t postgresql, postgresql_response_t response) {
        // Process subset of error messages, that will help to diagnoze the startup message failure (full list: https://www.postgresql.org/docs/current/protocol-error-fields.html)
        postgresql_error_t errorSeverity = NULL;
        postgresql_error_t errorCode = NULL;
        postgresql_error_t errorMessage = NULL;
        for (postgresql_error_t error = (postgresql_error_t)&(response->data.buffer); error->type != 0; error = (postgresql_error_t)((char *)error + 1 + strlen(error->value) + 1)) {
                switch (error->type) {
                        case PostgreSQLError_SeverityLocalized:
                                errorSeverity = error;
                                break;
                        case PostgreSQLError_SeverityNative: // Postgresql 9.6 or later
                                errorSeverity = error;
                                break;
                        case PostgreSQLError_Code:
                                errorCode = error;
                                break;
                        case PostgreSQLError_Message:
                                errorMessage = error;
                                break;
                        default:
                                break;
                }
        }
        if (postgresql->state == PostgreSQL_Init && ! postgresql->port->parameters.postgresql.username && ! postgresql->port->parameters.postgresql.database) {
                // Backward compatibility: Monit < 5.29.0 used a hardcoded user and database, hence it interpreted the error as a sign that the server is able to respond (regardless of result). 
                // Monit > 5.29.0 allows to set custom user and database, hence we expect successful response here and will throw error.
                DEBUG("PGSQL: error message received, but as no custom user or database is set, accept it for backward compatibility with Monit < 5.29.0 -- Severity=%s, Code=%s, Message=%s\n", PGERROR(errorSeverity), PGERROR(errorCode), PGERROR(errorMessage));
        } else {
                THROW(IOException, "PGSQL: startup message error -- Severity=%s, Code=%s, Message=%s", PGERROR(errorSeverity), PGERROR(errorCode), PGERROR(errorMessage));
        }
        postgresql->state = PostgreSQL_Error;
}


static void _handleAuthentication(postgresql_t postgresql, postgresql_response_t response) {
        postgresql_response_authentication_t a = &(response->data.authentication);
        PostgreSQLAuthentication authenticationType = ntohl(a->type);
        DEBUG("PGSQL: authentication message received, type=%d\n", authenticationType);
        switch (authenticationType) {
                case PostgreSQLAuthentication_Ok:
                        DEBUG("PGSQL: authentication OK\n");
                        postgresql->state = PostgreSQL_AuthenticationOk;
                        break;
                case PostgreSQLAuthentication_CleartextPassword:
                        DEBUG("PGSQL: clear text password authentication required\n");
                        postgresql->authentication.callback = _authenticateClearPassword;
                        postgresql->state = PostgreSQL_AuthenticationNeeded;
                        break;
                case PostgreSQLAuthentication_MD5Password:
                        DEBUG("PGSQL: MD5 password authentication required, salt %.2x%.2x%.2x%.2x\n", a->data.md5.salt[0], a->data.md5.salt[1], a->data.md5.salt[2], a->data.md5.salt[3]);
                        postgresql->state = PostgreSQL_AuthenticationNeeded;
                        memcpy(postgresql->authentication.salt, a->data.md5.salt, sizeof(a->data.md5.salt));
                        postgresql->authentication.callback = _authenticateMd5;
                        break;
                default:
                        DEBUG("PGSQL: authentication method type %d not supported, stopping the protocol test here with success (server communicates)\n", authenticationType);
                        postgresql->state = PostgreSQL_AuthenticationNeededUnknownType;
                        break;
        }
}


static void _handleResponse(postgresql_t postgresql) {
        struct postgresql_response_t response = {};

        // Read in the response header (packet type and payload length)
        int rv = Socket_read(postgresql->socket, &response, sizeof(struct postgresql_response_header_t));
        if (rv < 0)
                THROW(IOException, "PGSQL: response header read error -- %s", STRERROR);
        else if (rv != sizeof(struct postgresql_response_header_t))
                THROW(IOException, "PGSQL: response header read error -- %d bytes expected, got %d bytes", sizeof(struct postgresql_response_header_t), rv);

        // Payload length to host order
        int payloadLength = ntohl(response.header.length);
        DEBUG("PGSQL: response payload %d bytes\n", payloadLength);

        // Subtract the payload part which we read already (the 'length' attribute size)
        size_t remainingPayloadLength = payloadLength - sizeof(response.header.length);

        // Sanity check (our current limit is 1Kb as we don't implement SQL queries and need only session setup messages)
        if (remainingPayloadLength > sizeof(response.data.buffer))
                THROW(IOException, "PGSQL: response message is too large: %d bytes received (maximum %d)", remainingPayloadLength, sizeof(response.data.buffer));

        // Read the response payload
        rv = Socket_read(postgresql->socket, &response.data.buffer, remainingPayloadLength);
        if (rv < 0)
                THROW(IOException, "PGSQL: response payload read error -- %s", STRERROR);
        else if (rv != (int)remainingPayloadLength)
                THROW(IOException, "PGSQL: response payload read error -- %d bytes expected, got %d bytes", remainingPayloadLength, rv);

        if (response.header.type == PostgreSQLPacket_Error)
                _handleError(postgresql, &response);
        else if (response.header.type == PostgreSQLPacket_Authentication)
                _handleAuthentication(postgresql, &response);
}


/* ---------------------------------------------------------------- Public */


/**
 *  PostgreSQL test.
 *
 *  @file
 */
void check_pgsql(Socket_T S) {
        ASSERT(S);

        struct postgresql_t postgresql = {
                .state = PostgreSQL_Init,
                .socket = S,
                .port = Socket_getPort(S)
        };

        // Send startup message
        _requestStartup(&postgresql);

        // Read startup message response
        _handleResponse(&postgresql);

        // Handle authentication if needed
        if (postgresql.state == PostgreSQL_AuthenticationNeeded) {
                postgresql.authentication.callback(&postgresql);
                _handleResponse(&postgresql);
        }

        /*FIXME:
          handle packets that may follow authentication response:
                        1) if database doesn't exist, but the authentication succeeded, authentication ok message is returned, followed by error (standalone message), that specifies details about the invalid database
                        2) if authentication succeeded and there was no error, the auth ok packet is followed by bunch of ParameterStatus packets, that provide for example info about the db server version ... log it?
                        3) ditto 2, but the last ParameterStatus is followed by ReadyForQuery packet ... should we check for it? (i.e. the protocol test doesn't succeed until ReadyForQuery is received?)
         */

        // Terminate the session
        if (postgresql.port->family != Socket_Unix)
                _requestTerminate(&postgresql);
}

