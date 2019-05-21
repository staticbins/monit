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

#include "protocol.h"

// libmonit
#include "exceptions/IOException.h"
#include "exceptions/ProtocolException.h"


/* ----------------------------------------------------------- Definitions */


// Message type (see http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718021)
typedef enum {
        MQTT_Type_ConnectRequest = 1,
        MQTT_Type_ConnectResponse,
        MQTT_Type_PublishRequest,
        MQTT_Type_PublishResponse,
        MQTT_Type_PublishReceived,
        MQTT_Type_PublishRelease,
        MQTT_Type_PublishComplete,
        MQTT_Type_SubscribeRequest,
        MQTT_Type_SubscribeResponse,
        MQTT_Type_UnsubscribeRequest,
        MQTT_Type_UnsubscribeResponse,
        MQTT_Type_PingRequest,
        MQTT_Type_PingResponse,
        MQTT_Type_Disconnect
} __attribute__((__packed__)) MQTT_Type;


// Connect request flags (see http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718030) - we use just subset for CONNECT and DISCONNECT
typedef enum {
        MQTT_ConnectRequest_CleanSession = 0x02,
        MQTT_ConnectRequest_Password     = 0x40,
        MQTT_ConnectRequest_Username     = 0x80
} __attribute__((__packed__)) MQTT_ConnectRequest_Flags;


// Connect response flags (see http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Toc398718035)
typedef enum {
        MQTT_ConnectResponse_Accepted = 0,
        MQTT_ConnectResponse_Refused_Protocol,
        MQTT_ConnectResponse_Refused_ClientIdentifier,
        MQTT_ConnectResponse_Refused_ServiceUnavailable,
        MQTT_ConnectResponse_Refused_Credentials
} __attribute__((__packed__)) MQTT_ConnectResponse_Codes;


/* -------------------------------------------------------------- Messages */


typedef struct {
#if BYTE_ORDER == LITTLE_ENDIAN
        uint8_t  flags       : 4;
        uint8_t  messageType : 4;
#else
        uint8_t  messageType : 4;
        uint8_t  flags       : 4;
#endif
        uint8_t  messageLength;
} mqtt_header_t;


typedef struct {
        uint16_t length;
        char     data[STRLEN];
} *mqtt_payload_t;


typedef struct {
        mqtt_header_t  header;
        uint16_t       protocolNameLength;
        char           protocolName[4];
        uint8_t        protocolLevel;
        uint8_t        flags;
        uint16_t       keepAlive;
        char           data[1024];
} mqtt_connect_request_t;


typedef struct {
        mqtt_header_t  header;
        uint8_t        acknowledgeFlags;
        uint8_t        returnCode;
} mqtt_connect_response_t;


typedef struct {
        mqtt_header_t  header;
} mqtt_disconnect_request_t;


typedef enum {
        MQTT_Init = 0,
        MQTT_Connected
} __attribute__((__packed__)) mqtt_state_t;


typedef struct mqtt_t {
        mqtt_state_t state;
        Socket_T socket;
        Port_T port;
} mqtt_t;


/* ------------------------------------------------------ Request handlers */


static boolean_t _connect(mqtt_t *mqtt) {
        mqtt_connect_request_t connect = {
                .header.messageType = MQTT_Type_ConnectRequest,
                .header.flags       = 0,
                .protocolNameLength                 = htons(4),
                .protocolName[0]                    = 'M',
                .protocolName[1]                    = 'Q',
                .protocolName[2]                    = 'T',
                .protocolName[3]                    = 'T',
                .protocolLevel                      = 4,    // protocol for version 3.1.1
                .flags                              = MQTT_ConnectRequest_CleanSession, //FIXME: support MQTT_ConnectRequest_Password + MQTT_ConnectRequest_Username if set
                .keepAlive                          = htons(1)
        };
        // Client ID
        uint16_t *clientIdentifierLength = (uint16_t *)connect.data;
        char *clientIdentifierData = connect.data + sizeof(uint16_t);
        clientIdentifierData[0] = 'm';
        clientIdentifierData[1] = 'o';
        clientIdentifierData[2] = 'n';
        clientIdentifierData[3] = 'i';
        clientIdentifierData[4] = 't';
        clientIdentifierData[5] = '-';
        Util_getToken(clientIdentifierData + 6);
        *clientIdentifierLength = htons(strlen(clientIdentifierData));
        // Username
//        mqtt_payload_t userName = {};
        // Password
//        mqtt_payload_t password = {};
        //FIXME: implement connect with optional username and password
        connect.header.messageLength = sizeof(mqtt_connect_request_t) - sizeof(mqtt_header_t) - sizeof(connect.data) + 2 + strlen(clientIdentifierData);
        if (Socket_write(mqtt->socket, &connect, sizeof(mqtt_header_t) + 10 + 2 + strlen(clientIdentifierData)) < 0) {
                THROW(IOException, "Cannot connect -- %s\n", STRERROR);
        }
        //FIXME: check connect response
        mqtt->state = MQTT_Connected;
        return true;
}


static void _disconnect(mqtt_t *mqtt) {
        if (mqtt->state == MQTT_Connected) {
                mqtt_disconnect_request_t disconnect = {
                        .header.messageType   = MQTT_Type_Disconnect,
                        .header.flags         = 0,
                        .header.messageLength                 = 0
                };
                if (Socket_write(mqtt->socket, &disconnect, sizeof(mqtt_disconnect_request_t)) < 0) {
                        THROW(IOException, "Cannot disconnect -- %s\n", STRERROR);
                }
        }
        mqtt->state = MQTT_Init;
}


/* ---------------------------------------------------------------- Public */


/**
 * MQTT test. Connect and disconnect.
 *
 *  @see http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
 */
void check_mqtt(Socket_T socket) {
        ASSERT(socket);
        mqtt_t mqtt = {.state = MQTT_Init, .socket = socket, .port = Socket_getPort(socket)};
        _connect(&mqtt);
        _disconnect(&mqtt);
}

