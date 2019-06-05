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
        MQTT_ConnectRequest_None         = 0x00,
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
        MQTT_ConnectResponse_Refused_Credentials,
        MQTT_ConnectResponse_Refused_NotAuthorized
} __attribute__((__packed__)) MQTT_ConnectResponse_Codes;


/* -------------------------------------------------------------- Messages */


typedef struct {
#if BYTE_ORDER == LITTLE_ENDIAN
        uint8_t   flags       : 4;
        MQTT_Type messageType : 4;
#else
        MQTT_Type messageType : 4;
        uint8_t   flags       : 4;
#endif
        uint8_t   messageLength;
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
        MQTT_ConnectSent,
        MQTT_Connected
} __attribute__((__packed__)) mqtt_state_t;


typedef struct mqtt_t {
        mqtt_state_t state;
        Socket_T socket;
        Port_T port;
} mqtt_t;


/* ------------------------------------------------------ Request handlers */


static const char *_describeType(int type) {
        switch (type) {
                case MQTT_Type_ConnectRequest:
                        return "Connect Request";
                case MQTT_Type_ConnectResponse:
                        return "Connect Response";
                case MQTT_Type_PublishRequest:
                        return "Publish Request";
                case MQTT_Type_PublishResponse:
                        return "Publish Response";
                case MQTT_Type_PublishReceived:
                        return "Publish Received";
                case MQTT_Type_PublishRelease:
                        return "Publish Release";
                case MQTT_Type_PublishComplete:
                        return "Publish Complete";
                case MQTT_Type_SubscribeRequest:
                        return "Subscribe Request";
                case MQTT_Type_SubscribeResponse:
                        return "Subscribe Response";
                case MQTT_Type_UnsubscribeRequest:
                        return "Unsubscribe Request";
                case MQTT_Type_UnsubscribeResponse:
                        return "Unsubscribe Response";
                case MQTT_Type_PingRequest:
                        return "Ping Request";
                case MQTT_Type_PingResponse:
                        return "Ping Response";
                case MQTT_Type_Disconnect:
                        return "Disconnect";
                default:
                        break;
        }
        return "unknown";
}


static const char *_describeConnectionCode(int code) {
        switch (code) {
                case MQTT_ConnectResponse_Accepted:
                        return "Connection accepted";
                case MQTT_ConnectResponse_Refused_Protocol:
                        return "Connection Refused: unacceptable protocol version";
                case MQTT_ConnectResponse_Refused_ClientIdentifier:
                        return "Connection Refused: client identifier rejected";
                case MQTT_ConnectResponse_Refused_ServiceUnavailable:
                        return "Connection Refused: server unavailable";
                case MQTT_ConnectResponse_Refused_Credentials:
                        return "Connection Refused: bad user name or password";
                case MQTT_ConnectResponse_Refused_NotAuthorized:
                        return "Connection Refused: not authorized";
                default:
                        break;
        }
        return "unknown";
}


static void _payload(mqtt_connect_request_t *request, const char *data, MQTT_ConnectRequest_Flags flags) {
        size_t dataLength = strlen(data);
        mqtt_payload_t payload = (mqtt_payload_t)(request->data + request->header.messageLength);
        strncpy(payload->data, data, dataLength);
        payload->length = htons(dataLength);
        request->header.messageLength += sizeof(payload->length) + dataLength;
        request->flags |= flags;
}


static void _connectRequest(mqtt_t *mqtt) {
        mqtt_connect_request_t connect = {
                .header.messageType                 = MQTT_Type_ConnectRequest,
                .header.flags                       = 0,
                .protocolNameLength                 = htons(4),
                .protocolName[0]                    = 'M',
                .protocolName[1]                    = 'Q',
                .protocolName[2]                    = 'T',
                .protocolName[3]                    = 'T',
                .protocolLevel                      = 4,    // protocol for version 3.1.1
                .flags                              = MQTT_ConnectRequest_CleanSession,
                .keepAlive                          = htons(1)
        };

        // Client ID
        char id[STRLEN] = {};
        snprintf(id, sizeof(id), "monit-%lld", (long long)Run.incarnation);
        _payload(&connect, id, MQTT_ConnectRequest_None);

        // Username
        if (mqtt->port->parameters.mqtt.username) {
                _payload(&connect, mqtt->port->parameters.mqtt.username, MQTT_ConnectRequest_Username);
        }

        // Password
        if (mqtt->port->parameters.mqtt.password) {
                _payload(&connect, mqtt->port->parameters.mqtt.password, MQTT_ConnectRequest_Password);
        }

        connect.header.messageLength += sizeof(mqtt_connect_request_t) - sizeof(mqtt_header_t) - sizeof(connect.data);

        if (Socket_write(mqtt->socket, &connect, sizeof(mqtt_header_t) + connect.header.messageLength) < 0) {
                THROW(IOException, "Cannot connect -- %s\n", STRERROR);
        }
        mqtt->state = MQTT_ConnectSent;
}


static void _connectResponse(mqtt_t *mqtt) {
        mqtt_connect_response_t response = {};
        if (Socket_read(mqtt->socket, &response, sizeof(mqtt_connect_response_t)) < sizeof(mqtt_connect_response_t)) {
                THROW(IOException, "Error receiving connection response -- %s", STRERROR);
        }
        if (response.header.messageType != MQTT_Type_ConnectResponse) {
                THROW(ProtocolException, "Unexpected connection response type -- %s (%d)", _describeType(response.header.messageType), response.header.messageType);
        }
        if (response.header.messageLength != 2) {
                THROW(ProtocolException, "Unexpected connection response length -- %d", response.header.messageLength);
        }
        if (response.returnCode != MQTT_ConnectResponse_Accepted) {
                THROW(ProtocolException, "Unexpected connection response code -- %s (%d)", _describeConnectionCode(response.returnCode), response.returnCode);
        }
        mqtt->state = MQTT_Connected;
}


static void _disconnect(mqtt_t *mqtt) {
        if (mqtt->state == MQTT_Connected) {
                mqtt_disconnect_request_t disconnect = {
                        .header.messageType   = MQTT_Type_Disconnect,
                        .header.flags         = 0,
                        .header.messageLength = 0
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
        _connectRequest(&mqtt);
        _connectResponse(&mqtt);
        _disconnect(&mqtt);
}

