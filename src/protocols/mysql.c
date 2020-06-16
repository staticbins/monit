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

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "protocol.h"
#include "md5.h"
#include "sha1.h"
#include "checksum.h"

// libmonit
#include "exceptions/IOException.h"
#include "exceptions/ProtocolException.h"


/* ----------------------------------------------------------- Definitions */


#define MYSQL_OK           0x00
#define MYSQL_AUTHMOREDATA 0x01
#define MYSQL_AUTHSWITCH   0xfe
#define MYSQL_ERROR        0xff


#define COM_QUIT  0x1
#define COM_QUERY 0x3
#define COM_PING  0xe


// Capability flags (see http://dev.mysql.com/doc/internals/en/capability-flags.html#packet-Protocol::CapabilityFlags)
#define CLIENT_LONG_PASSWORD                  0x00000001
#define CLIENT_FOUND_ROWS                     0x00000002
#define CLIENT_LONG_FLAG                      0x00000004
#define CLIENT_CONNECT_WITH_DB                0x00000008
#define CLIENT_NO_SCHEMA                      0x00000010
#define CLIENT_COMPRESS                       0x00000020
#define CLIENT_ODBC                           0x00000040
#define CLIENT_LOCAL_FILES                    0x00000080
#define CLIENT_IGNORE_SPACE                   0x00000100
#define CLIENT_PROTOCOL_41                    0x00000200
#define CLIENT_INTERACTIVE                    0x00000400
#define CLIENT_SSL                            0x00000800
#define CLIENT_IGNORE_SIGPIPE                 0x00001000
#define CLIENT_TRANSACTIONS                   0x00002000
#define CLIENT_RESERVED                       0x00004000
#define CLIENT_SECURE_CONNECTION              0x00008000
#define CLIENT_MULTI_STATEMENTS               0x00010000
#define CLIENT_MULTI_RESULTS                  0x00020000
#define CLIENT_PS_MULTI_RESULTS               0x00040000
#define CLIENT_PLUGIN_AUTH                    0x00080000
#define CLIENT_CONNECT_ATTRS                  0x00100000
#define CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA 0x00200000
#define CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS   0x00400000
#define CLIENT_SESSION_TRACK                  0x00800000
#define CLIENT_DEPRECATE_EOF                  0x01000000
#define CLIENT_SSL_VERIFY_SERVER_CERT         0x40000000
#define CLIENT_REMEMBER_OPTIONS               0x80000000


// Status flags (see http://dev.mysql.com/doc/internals/en/status-flags.html#packet-Protocol::StatusFlags)
#define SERVER_STATUS_IN_TRANS                0x0001
#define SERVER_STATUS_AUTOCOMMIT              0x0002
#define SERVER_MORE_RESULTS_EXISTS            0x0008
#define SERVER_STATUS_NO_GOOD_INDEX_USED      0x0010
#define SERVER_STATUS_NO_INDEX_USED           0x0020
#define SERVER_STATUS_CURSOR_EXISTS           0x0040
#define SERVER_STATUS_LAST_ROW_SENT           0x0080
#define SERVER_STATUS_DB_DROPPED              0x0100
#define SERVER_STATUS_NO_BACKSLASH_ESCAPES    0x0200
#define SERVER_STATUS_METADATA_CHANGED        0x0400
#define SERVER_QUERY_WAS_SLOW                 0x0800
#define SERVER_PS_OUT_PARAMS                  0x1000
#define SERVER_STATUS_IN_TRANS_READONLY       0x2000
#define SERVER_SESSION_STATE_CHANGED          0x4000


#define MYSQL_REQUEST_BUFFER                  4096
#define MYSQL_RESPONSE_BUFFER                 4096

#ifndef HAVE_OPENSSL
#define SHA256_DIGEST_LENGTH 32
#endif

typedef struct {
        uint32_t len : 24;
        uint32_t seq : 8;
        // Data buffer
        char buf[MYSQL_REQUEST_BUFFER];
        // State
        char *cursor;
        char *limit;
} mysql_request_t;


typedef struct {
        // Data buffer
        char buf[MYSQL_RESPONSE_BUFFER + 4 + 1]; // reserve 4 bytes for header
        // Parser state
        char *cursor;
        char *limit;
        // Header
        int32_t len;
        uint8_t seq;
        uint8_t header;
        // Packet specific data
        union {
                struct {
                        // https://dev.mysql.com/doc/dev/mysql-server/8.0.11/page_protocol_connection_phase_packets_protocol_handshake_v10.html
                        char     *version;
                        uint32_t  connectionid;
                        uint8_t   characterset;
                        uint16_t  status;
                        uint32_t  capabilities;
                        uint8_t   authdatalen;
                        char      authdata[21];
                        char      authplugin[64];
                } handshake;
                struct {
                        // https://dev.mysql.com/doc/dev/mysql-server/8.0.11/page_protocol_connection_phase_packets_protocol_auth_more_data.html
                } authmoredata;
                struct {
                        // https://dev.mysql.com/doc/dev/mysql-server/8.0.11/page_protocol_basic_err_packet.html
                        uint16_t  code;
                        char      sql_state_marker;
                        char      sql_state[5];
                        char     *message;
                } error;
        } data;
} mysql_response_t;


typedef enum {
        MySQL_Init = 0,
        MySQL_Greeting,
        MySQL_Ssl,
        MySQL_Handshake,
        MySQL_FastAuthSuccess,
        MySQL_FullAuthenticationNeeded,
        MySQL_FetchRSAKey,
        MySQL_PasswordSent,
        MySQL_AuthSwitch,
        MySQL_Ok,
        MySQL_Error
} __attribute__((__packed__)) mysql_state_t;


typedef enum {
        Auth_Native = 0,
        Auth_CachingSha2
} __attribute__((__packed__)) mysql_authentication_t;


typedef struct mysql_t {
        uint8_t sequence;
        mysql_state_t state;
        struct {
                mysql_authentication_t type;
                int hashLength;
                char *(*getPassword)(char *result, const char *password, const char *salt);
        } authentication;
        mysql_response_t response;
        mysql_request_t request;
        Socket_T socket;
        Port_T port;
        uint32_t capabilities;
        char salt[21];
        char publicKey[4096];
} mysql_t;


/* ----------------------------------------------------------- Data parser */


static uint8_t _getUInt1(mysql_response_t *response) {
        if (response->cursor + 1 > response->limit)
                THROW(ProtocolException, "Data not available -- EOF");
        uint8_t value = response->cursor[0];
        response->cursor += 1;
        return value;
}


static uint16_t _getUInt2(mysql_response_t *response) {
        if (response->cursor + 2 > response->limit)
                THROW(ProtocolException, "Data not available -- EOF");
        uint16_t value;
        *(((char *)&value) + 0) = response->cursor[1];
        *(((char *)&value) + 1) = response->cursor[0];
        response->cursor += 2;
        return ntohs(value);
}


static uint32_t _getUInt3(mysql_response_t *response) {
        if (response->cursor + 3 > response->limit)
                THROW(ProtocolException, "Data not available -- EOF");
        uint32_t value;
        *(((char *)&value) + 0) = 0;
        *(((char *)&value) + 1) = response->cursor[2];
        *(((char *)&value) + 2) = response->cursor[1];
        *(((char *)&value) + 3) = response->cursor[0];
        response->cursor += 3;
        return ntohl(value);
}


static uint32_t _getUInt4(mysql_response_t *response) {
        if (response->cursor + 4 > response->limit)
                THROW(ProtocolException, "Data not available -- EOF");
        uint32_t value;
        *(((char *)&value) + 0) = response->cursor[3];
        *(((char *)&value) + 1) = response->cursor[2];
        *(((char *)&value) + 2) = response->cursor[1];
        *(((char *)&value) + 3) = response->cursor[0];
        response->cursor += 4;
        return ntohl(value);
}


static char *_getString(mysql_response_t *response) {
        int i;
        char *value;
        for (i = 0; response->cursor[i]; i++) // Check limits (cannot use strlen here as no terminating '\0' is guaranteed in the buffer)
                if (response->cursor + i >= response->limit) // If we reached the limit and didn't found '\0', throw error
                        THROW(ProtocolException, "Data not available -- EOF");
        value = response->cursor;
        response->cursor += i + 1;
        return value;
}


static void _getPadding(mysql_response_t *response, int count) {
        if (response->cursor + count > response->limit)
                THROW(ProtocolException, "Data not available -- EOF");
        response->cursor += count;
}


/* ----------------------------------------------------------- Data setter */


static void _setUInt1(mysql_request_t *request, uint8_t value) {
        if (request->cursor + 1 > request->limit)
                THROW(ProtocolException, "Maximum packet size exceeded");
        request->cursor[0] = value;
        request->cursor += 1;
}


static void _setUInt4(mysql_request_t *request, uint32_t value) {
        if (request->cursor + 4 > request->limit)
                THROW(ProtocolException, "Maximum packet size exceeded");
        uint32_t v = htonl(value);
        request->cursor[0] = *(((char *)&v) + 3);
        request->cursor[1] = *(((char *)&v) + 2);
        request->cursor[2] = *(((char *)&v) + 1);
        request->cursor[3] = *(((char *)&v) + 0);
        request->cursor += 4;
}


static void _setData(mysql_request_t *request, const char *data, unsigned long length) {
        if (request->cursor + length > request->limit)
                THROW(ProtocolException, "Maximum packet size exceeded");
        memcpy(request->cursor, data, length);
        request->cursor += length;
}


static void _setPadding(mysql_request_t *request, int count) {
        if (request->cursor + count > request->limit)
                THROW(ProtocolException, "Maximum packet size exceeded");
        request->cursor += count;
}


/* ----------------------------------------------------- Response handlers */


// OK packet (see http://dev.mysql.com/doc/internals/en/packet-OK_Packet.html)
static void _responseOk(mysql_t *mysql) {
        mysql->state = MySQL_Ok;
}


// AuthMoreData packet
static void _responseAuthMoreData(mysql_t *mysql) {
        if (mysql->state == MySQL_Handshake) {
                uint8_t data = _getUInt1(&mysql->response);
                switch (data) {
                        case 3:
                                // Success
                                mysql->state = MySQL_FastAuthSuccess;
                                DEBUG("MySQL Fast Authentication success\n");
                                break;
                        case 4:
                                // Full authentication is needed
                                mysql->state = MySQL_FullAuthenticationNeeded;
                                DEBUG("MySQL Full Authentication required\n");
                                break;
                        default:
                                THROW(ProtocolException, "Unexpected AuthMoreData message as part of caching_sha2_password authentication: 0x%x", data);
                                break;
                }
        } else if (mysql->state == MySQL_FetchRSAKey) {
                // Fetch the RSA key
                if ((size_t)mysql->response.len >= sizeof(mysql->publicKey)) {
                        THROW(ProtocolException, "AuthMoreData response too large: %d", mysql->response.len);
                } else {
                        strncpy(mysql->publicKey, _getString(&mysql->response), sizeof(mysql->publicKey) - 1);
                }
        } else {
                THROW(ProtocolException, "Unexpected AuthMoreData message -- current state %d", mysql->state);
        }
}


// Get the password (see http://dev.mysql.com/doc/internals/en/secure-password-authentication.html):
static char *_getNativePassword(char result[static SHA1_DIGEST_SIZE], const char *password, const char *salt) {
        sha1_context_t ctx;
        // SHA1(password)
        uint8_t stage1[SHA1_DIGEST_SIZE];
        sha1_init(&ctx);
        sha1_append(&ctx, (const unsigned char *)password, strlen(password));
        sha1_finish(&ctx, stage1);
        // SHA1(SHA1(password))
        uint8_t stage2[SHA1_DIGEST_SIZE];
        sha1_init(&ctx);
        sha1_append(&ctx, (const unsigned char *)stage1, SHA1_DIGEST_SIZE);
        sha1_finish(&ctx, stage2);
        // SHA1("20-bytes random data from server" <concat> SHA1(SHA1(password)))
        uint8_t stage3[SHA1_DIGEST_SIZE];
        sha1_init(&ctx);
        sha1_append(&ctx, (const unsigned char *)salt, strlen(salt));
        sha1_append(&ctx, (const unsigned char *)stage2, SHA1_DIGEST_SIZE);
        sha1_finish(&ctx, stage3);
        // XOR
        for (int i = 0; i < SHA1_DIGEST_SIZE; i++)
                result[i] = stage1[i] ^ stage3[i];
        return result;
}


// Get the password (see https://dev.mysql.com/doc/internals/en/sha256.html and https://dev.mysql.com/doc/dev/mysql-server/8.0.11/page_caching_sha2_authentication_exchanges.html):
static char *_getCachingSha2Password(char result[static SHA256_DIGEST_LENGTH], const char *password, const char *salt) {
#ifdef HAVE_OPENSSL
        // SHA256(password)
        uint8_t stage1[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char *)password, strlen(password), stage1);

        // SHA256(SHA256(password))
        uint8_t stage2[SHA256_DIGEST_LENGTH];
        SHA256(stage1, SHA256_DIGEST_LENGTH, stage2);

        // SHA256(SHA256(SHA256(password)), Nonce)
        uint8_t stage3[SHA256_DIGEST_LENGTH];
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, stage2, SHA256_DIGEST_LENGTH);
        SHA256_Update(&ctx, salt, strlen(salt));
        SHA256_Final(stage3, &ctx);

        // XOR(SHA256(password), SHA256(SHA256(SHA256(password)), Nonce))
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
                result[i] = stage1[i] ^ stage3[i];
#else
        THROW(ProtocolException, "MYSQL: caching_sha2_password authentication requires monit to be compiled with SSL library");
#endif
        return result;
}


static void _parsePlugin(mysql_t *mysql, const char *plugin) {
        DEBUG("Server wants %s plugin\n", plugin);
        if (IS(plugin, "caching_sha2_password")) {
                mysql->authentication.type = Auth_CachingSha2;
                mysql->authentication.hashLength = SHA256_DIGEST_LENGTH;
                mysql->authentication.getPassword = _getCachingSha2Password;
                snprintf(mysql->response.data.handshake.authplugin, sizeof(mysql->response.data.handshake.authplugin), "%s", plugin);
                DEBUG("Will use caching_sha2_password plugin\n");
        } else if (IS(plugin, "mysql_native_password")) {
                mysql->authentication.type = Auth_Native;
                mysql->authentication.hashLength = SHA1_DIGEST_SIZE;
                mysql->authentication.getPassword = _getNativePassword;
                snprintf(mysql->response.data.handshake.authplugin, sizeof(mysql->response.data.handshake.authplugin), "%s", plugin);
                DEBUG("Will use mysql_native_password plugin\n");
        } else {
                THROW(ProtocolException, "MYSQL: unsupported authentication plugin: %s", plugin);
        }
}


// AuthSwitchRequest (see https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_auth_switch_request.html)
static void _responseAuthSwitch(mysql_t *mysql) {
        DEBUG("AuthSwitch request from the server\n");
        mysql->state = MySQL_AuthSwitch;
        if (mysql->capabilities & CLIENT_PLUGIN_AUTH) {
                // New plugin name
                _parsePlugin(mysql, _getString(&mysql->response));
                // New salt
                snprintf(mysql->salt, sizeof(mysql->salt), "%s", _getString(&mysql->response));
        } else {
                THROW(ProtocolException, "Unexpected AuthSwitchRequest -- the server doesn't support plugin authentication");
        }
}


// ERR packet (see http://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html)
static void _responseError(mysql_t *mysql) {
        mysql->state = MySQL_Error;
        mysql->response.data.error.code = _getUInt2(&mysql->response);
        if (mysql->capabilities & CLIENT_PROTOCOL_41)
                _getPadding(&mysql->response, 6); // skip sql_state_marker and sql_state which we don't use
        mysql->response.data.error.message = _getString(&mysql->response);
        THROW(ProtocolException, "Server returned error code %d -- %s", mysql->response.data.error.code, mysql->response.data.error.message);
}


// Initial greeting packet (see http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake)
static void _greeting(mysql_t *mysql) {
        mysql->state = MySQL_Greeting;
        // Protocol is 10 for MySQL 5.x
        if (mysql->response.header != 10)
                THROW(ProtocolException, "Invalid protocol version %d", mysql->response.header);
        mysql->response.data.handshake.version = _getString(&mysql->response);
        mysql->response.data.handshake.connectionid = _getUInt4(&mysql->response);
        snprintf(mysql->salt, 9, "%s", _getString(&mysql->response)); // auth_plugin_data_part_1
        mysql->response.data.handshake.capabilities = _getUInt2(&mysql->response); // capability flags (lower 2 bytes)
        mysql->response.data.handshake.characterset = _getUInt1(&mysql->response);
        mysql->response.data.handshake.status = _getUInt2(&mysql->response);
        mysql->response.data.handshake.capabilities |= ((uint32_t)_getUInt2(&mysql->response) << 16); // merge capability flags (lower 2 bytes + upper 2 bytes)
        mysql->response.data.handshake.authdatalen = _getUInt1(&mysql->response);
        _getPadding(&mysql->response, 10); // reserved bytes
        if (mysql->response.data.handshake.capabilities & CLIENT_SECURE_CONNECTION)
                snprintf(mysql->salt + 8, 13, "%s", _getString(&mysql->response)); // auth_plugin_data_part_2
        mysql->capabilities = mysql->response.data.handshake.capabilities; // Save capabilities
        if (mysql->capabilities & CLIENT_PLUGIN_AUTH) {
                _parsePlugin(mysql, _getString(&mysql->response));
        }
        DEBUG("MySQL Server: Protocol: %d, Version: %s, Connection ID: %d, Capabilities: 0x%x, AuthPlugin: %s\n", mysql->response.header, mysql->response.data.handshake.version, mysql->response.data.handshake.connectionid, mysql->response.data.handshake.capabilities, *mysql->response.data.handshake.authplugin ? mysql->response.data.handshake.authplugin : "N/A");
}


// Response handler
static void _readResponse(mysql_t *mysql) {
        memset(&mysql->response, 0, sizeof(mysql_response_t));
        mysql->response.cursor = mysql->response.buf;
        mysql->response.limit = mysql->response.buf + sizeof(mysql->response.buf);
        // Read the packet length
        if (Socket_read(mysql->socket, mysql->response.cursor, 4) < 4)
                THROW(IOException, "Error receiving server response -- %s", STRERROR);
        mysql->response.len = _getUInt3(&mysql->response);
        mysql->response.seq = _getUInt1(&mysql->response);
        if (mysql->state == MySQL_Init) {
                if (! mysql->response.len || mysql->response.len > MYSQL_RESPONSE_BUFFER)
                        THROW(ProtocolException, "Invalid handshake packet length -- not MySQL protocol");
                if (mysql->response.seq != 0)
                        THROW(ProtocolException, "Invalid handshake packet sequence id -- not MySQL protocol");
        }
        if (mysql->response.len > MYSQL_RESPONSE_BUFFER) {
                DEBUG("MySQL response: The response length %d is too large for our buffer, will read just %d\n", mysql->response.len, MYSQL_RESPONSE_BUFFER);
                mysql->response.len = MYSQL_RESPONSE_BUFFER;
        }
        mysql->response.len = mysql->response.len > MYSQL_RESPONSE_BUFFER ? MYSQL_RESPONSE_BUFFER : mysql->response.len; // Adjust packet length for this buffer
        // Read payload
        if (Socket_read(mysql->socket, mysql->response.cursor, mysql->response.len) != mysql->response.len)
                THROW(IOException, "Error receiving server response -- %s", STRERROR);
        // Packet type router
        mysql->response.header = _getUInt1(&mysql->response);
        switch (mysql->response.header) {
                case MYSQL_OK:
                        _responseOk(mysql);
                        break;
                case MYSQL_AUTHMOREDATA:
                        _responseAuthMoreData(mysql);
                        break;
                case MYSQL_AUTHSWITCH:
                        _responseAuthSwitch(mysql);
                        break;
                case MYSQL_ERROR:
                        _responseError(mysql);
                        break;
                default:
                        _greeting(mysql);
                        break;
        }
        mysql->sequence = mysql->response.seq + 1;
}


/* ------------------------------------------------------ Request handlers */


// Initiate the request
static void _initRequest(mysql_t *mysql) {
        memset(&mysql->request, 0, sizeof(mysql_request_t));
        mysql->request.seq = mysql->sequence++;
        mysql->request.cursor = mysql->request.buf;
        mysql->request.limit = mysql->request.buf + sizeof(mysql->request.buf);
}


// Set payload length and send the request to the server
static void _sendRequest(mysql_t *mysql, mysql_state_t targetState) {
        mysql->request.len = (uint32_t)(mysql->request.cursor - mysql->request.buf);
        // Send request
        if (Socket_write(mysql->socket, &mysql->request, mysql->request.len + 4) < 0) // Note: mysql->request.len value is just payload size + need to add 4 bytes for the header itself (len + seq)
                THROW(IOException, "Cannot send handshake response -- %s", STRERROR);
        mysql->state = targetState;
}


// Hadshake response packet (see http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse)
static void _sendHandshake(mysql_t *mysql) {
        if (mysql->state != MySQL_Greeting && mysql->state != MySQL_Ssl && mysql->state != MySQL_AuthSwitch)
                THROW(ProtocolException, "Unexpected communication state %d before handshake", mysql->state);
        _initRequest(mysql);
        uint32_t capabilities = CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION;
        if (Socket_isSecure(mysql->socket))
                capabilities |= CLIENT_SSL;
        // Does the server support plugin authentication? If yes, we announce we do as well
        if (mysql->capabilities & CLIENT_PLUGIN_AUTH)
                capabilities |= CLIENT_PLUGIN_AUTH;
        _setUInt4(&mysql->request, capabilities);  // capabilities
        _setUInt4(&mysql->request, 8192);          // maxpacketsize
        _setUInt1(&mysql->request, 8);             // characterset
        _setPadding(&mysql->request, 23);          // reserved bytes
        if (mysql->port->parameters.mysql.username)
                _setData(&mysql->request, mysql->port->parameters.mysql.username, strlen(mysql->port->parameters.mysql.username)); // username
        _setPadding(&mysql->request, 1);                                                                                           // NUL
        if (STR_DEF(mysql->port->parameters.mysql.password)) {
                char password[SHA256_DIGEST_LENGTH] = {};
                _setUInt1(&mysql->request, mysql->authentication.hashLength); // authdatalen
                _setData(&mysql->request, mysql->authentication.getPassword(password, mysql->port->parameters.mysql.password, mysql->salt), mysql->authentication.hashLength); // password
        } else {
                // empty password
                _setUInt1(&mysql->request, 0);
        }
        if (mysql->capabilities & CLIENT_PLUGIN_AUTH) {
                _setData(&mysql->request, mysql->response.data.handshake.authplugin, strlen(mysql->response.data.handshake.authplugin) + 1); // auth plugin
        }
        _sendRequest(mysql, MySQL_Handshake);
        DEBUG("MySQL handshake sent\n");
}


// SSL request packet (see https://dev.mysql.com/doc/dev/mysql-server/8.0.11/page_protocol_connection_phase_packets_protocol_ssl_request.html)
static void _sendSSLRequest(mysql_t *mysql) {
        if (mysql->state != MySQL_Greeting)
                THROW(ProtocolException, "Unexpected communication state %d before SSL start", mysql->state);
        _initRequest(mysql);
        _setUInt4(&mysql->request, CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH | CLIENT_SSL); // capabilities
        _setUInt4(&mysql->request, 8192);                                                                                                   // maxpacketsize
        _setUInt1(&mysql->request, 8);                                                                                                      // characterset
        _setPadding(&mysql->request, 23);                                                                                                   // reserved bytes
        _sendRequest(mysql, MySQL_Ssl);
        DEBUG("MySQL SSL request sent\n");
}


// RSA key request (see https://dev.mysql.com/doc/mysql-security-excerpt/8.0/en/caching-sha2-pluggable-authentication.html)
static void _sendRSAKeyRequest(mysql_t *mysql) {
        _initRequest(mysql);
        _setUInt1(&mysql->request, 2);
        _sendRequest(mysql, MySQL_FetchRSAKey);
        DEBUG("MySQL RSA key request sent\n");
}


// COM_QUIT packet (see http://dev.mysql.com/doc/internals/en/com-quit.html)
static void _sendQuit(mysql_t *mysql) {
        if (mysql->state != MySQL_Ok)
                THROW(ProtocolException, "Unexpected communication state %d before Quit", mysql->state);
        mysql->sequence = 0;
        _initRequest(mysql);
        _setUInt1(&mysql->request, COM_QUIT);
        _sendRequest(mysql, MySQL_Ok);
        DEBUG("MySQL QUIT sent\n");
}


static void _sendPassword(mysql_t *mysql, const unsigned char *password, int passwordLength) {
        if (mysql->state != MySQL_FullAuthenticationNeeded && mysql->state != MySQL_FetchRSAKey && mysql->state != MySQL_AuthSwitch)
                THROW(ProtocolException, "Unexpected communication state %d before password exchange", mysql->state);
        _initRequest(mysql);
        _setData(&mysql->request, (char *)password, passwordLength); // password
        _sendRequest(mysql, MySQL_PasswordSent);
        DEBUG("MySQL password sent\n");
}


// Send the RSA encrypted password (https://dev.mysql.com/doc/internals/en/not-so-fast-path.html)
static void _sendEncryptedPassword(mysql_t *mysql) {
#ifdef HAVE_OPENSSL
        // Parse the server RSA public key
        BIO *bio = BIO_new_mem_buf((void *)mysql->publicKey, -1);
        RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (! rsa)
                THROW(ProtocolException, "RSA public key load failed -- %s", ERR_error_string(ERR_get_error(), NULL));
        // XOR the password with the salt
        unsigned char saltedPassword[STRLEN];
        size_t saltLength = strlen(mysql->salt);
        size_t passwordLength = strlen(mysql->port->parameters.mysql.password) + 1; // Include the terminating NUL
        for (size_t i = 0; i < passwordLength; i++)
                saltedPassword[i] = mysql->port->parameters.mysql.password[i] ^ mysql->salt[i % saltLength];
        // RSA encrypt the salted password
        unsigned char encryptedPassword[RSA_size(rsa)];
        int encryptedPasswordLength = RSA_public_encrypt((int)passwordLength, saltedPassword, encryptedPassword, rsa, RSA_PKCS1_OAEP_PADDING);
        RSA_free(rsa);
        if (encryptedPasswordLength < 0) {
                THROW(ProtocolException, "RSA public encrypt failed -- %s", ERR_error_string(ERR_get_error(), NULL));
        }
        DEBUG("MySQL password encrypted successfully\n");
        // Send the encrypted password
        _sendPassword(mysql, encryptedPassword, encryptedPasswordLength);
#else
        THROW(ProtocolException, "MYSQL: _sendEncryptedPassword  requires monit to be compiled with SSL library");
#endif
}


static void _getRSAKey(mysql_t *mysql) {
        _sendRSAKeyRequest(mysql);
        _readResponse(mysql);
        DEBUG("MySQL RSA key retrieved successfully:\n%s\n", mysql->publicKey);
}


static void _checkRSAKey(mysql_t *mysql) {
        struct ChecksumContext_T context;
        Checksum_init(&context, mysql->port->parameters.mysql.rsaChecksumType);
        Checksum_append(&context, mysql->publicKey, (int)strlen(mysql->publicKey));
        Checksum_verify(&context, mysql->port->parameters.mysql.rsaChecksum);
        Checksum_verify(&context, mysql->port->parameters.mysql.rsaChecksum);
        DEBUG("MySQL RSA key checksum passed\n");
}


/*
// Note: we currently don't implement COM_QUERY *response* handler (OK/EOF packet with payload), if it'll be added and COM_QUERY used, uncomment the following COM_QUERY request implementation.
//
//   Usage (for example):
//      _requestQuery(&mysql, "show global status");
//

// COM_QUERY packet (see http://dev.mysql.com/doc/internals/en/com-query.html)
static void _requestQuery(mysql_t *mysql, const unsigned char *query) {
        ASSERT(mysql->state == MySQL_Ok);
        _initRequest(mysql);
        _setUInt1(&mysql->request, COM_QUERY);
        _setData(&mysql->request, query, strlen(query));
        _sendRequest(mysql, MySQL_Ok);
}
*/


/* ---------------------------------------------------------------- Public */


/**
 * Simple MySQL test. Connect to MySQL and read Server Handshake Packet. If we can read the packet and it is not an error packet we assume the server is up and working.
 *
 *  @see http://dev.mysql.com/doc/internals/en/client-server-protocol.html
 */
void check_mysql(Socket_T S) {
        ASSERT(S);
        mysql_t mysql = {
                .state = MySQL_Init,
                .sequence = 1,
                .authentication.type = Auth_Native,
                .authentication.hashLength = SHA1_DIGEST_SIZE,
                .authentication.getPassword = _getNativePassword,
                .socket = S,
                .port = Socket_getPort(S)
        };
        // Parse the server greeting
        _readResponse(&mysql);
        if (mysql.state != MySQL_Greeting)
                THROW(ProtocolException, "Invalid server greeting, the server didn't sent a handshake packet -- not MySQL protocol");
        if (mysql.port->parameters.mysql.username) {
                // If credentials are specified for the test, try to login
                if (mysql.port->target.net.ssl.options.flags == SSL_StartTLS) {
                        if (mysql.capabilities & CLIENT_SSL) {
                                // Send SSL request to the MySQL server (https://dev.mysql.com/doc/dev/mysql-server/8.0.11/page_protocol_connection_phase.html#sect_protocol_connection_phase_initial_handshake_ssl_handshake)
                                _sendSSLRequest(&mysql);
                                // Switch to TLS encryption
                                Socket_enableSsl(S, &(Run.ssl), NULL);
                        } else {
                                THROW(ProtocolException, "The MySQL server doesn't support SSL");
                        }
                }
                // Login
                _sendHandshake(&mysql);
                // The response to the handshake depends on authentication type. The native authentication sends just the OK message, the caching_sha2_password signalizes status using AuthMoreData
                _readResponse(&mysql);
                if (mysql.state == MySQL_AuthSwitch) {
                        if (STR_DEF(mysql.port->parameters.mysql.password)) {
                                // Resend the password encoded per requested plugin rules
                                char password[SHA256_DIGEST_LENGTH] = {};
                                _sendPassword(&mysql, (unsigned char *)mysql.authentication.getPassword(password, mysql.port->parameters.mysql.password, mysql.salt), mysql.authentication.hashLength);
                        } else {
                                // Send plain password
                                _sendPassword(&mysql, (unsigned char *)"", 0);
                        }
                        _readResponse(&mysql);
                } else if (mysql.state == MySQL_FastAuthSuccess) {
                        // The server should send an OK message immediately after fast auth success
                        _readResponse(&mysql);
                } else if (mysql.state == MySQL_FullAuthenticationNeeded) {
                        if (Socket_isSecure(S)) {
                                // Send the password to the server including the terminating NUL (plain as we use TLS already)
                                _sendPassword(&mysql, (unsigned char *)mysql.port->parameters.mysql.password, (int)strlen(mysql.port->parameters.mysql.password) + 1);
                                _readResponse(&mysql);
                        } else {
                                // unsecured channel: This requires encryption of the password with server's RSA public key. The client can:
                                // 1. either store a copy of server's public RSA key locally (safe) ... not implemented currently
                                // 2. or retrieve the key from the server (vulnerable to man-in-the-middle attack) => we allow to test the key fingerprint before submitting the password

                                // Get the server key
                                _getRSAKey(&mysql);
                                // Test the checksum
                                if (mysql.port->parameters.mysql.rsaChecksum) {
                                        _checkRSAKey(&mysql);
                                }
                                // Send password
                                _sendEncryptedPassword(&mysql);
                                _readResponse(&mysql);
                        }
                }
                _sendQuit(&mysql);
        }
}

