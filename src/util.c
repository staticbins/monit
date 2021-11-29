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

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_PAM_PAM_APPL_H
#include <pam/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#include "monit.h"
#include "engine.h"
#include "md5.h"
#include "md5_crypt.h"
#include "sha1.h"
#include "base64.h"
#include "alert.h"
#include "ProcessTree.h"
#include "event.h"
#include "state.h"
#include "protocol.h"
#include "checksum.h"

// libmonit
#include "io/File.h"
#include "util/Convert.h"
#include "system/Time.h"
#include "exceptions/AssertException.h"
#include "exceptions/IOException.h"


struct ad_user {
        const char *login;
        const char *passwd;
};


/* Unsafe URL characters: [00-1F, 7F-FF] <>\"#%}{|\\^[] ` */
static const unsigned char urlunsafe[256] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};


/* Unsafe URL characters for parameter value: [00-1F, 7F-FF] ?=&/<>\"#%}{|\\^[] ` */
static const unsigned char urlunsafeparameter[256] = {
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};


static const unsigned char b2x[][256] = {
        "00", "01", "02", "03", "04", "05", "06", "07",
        "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
        "10", "11", "12", "13", "14", "15", "16", "17",
        "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
        "20", "21", "22", "23", "24", "25", "26", "27",
        "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
        "30", "31", "32", "33", "34", "35", "36", "37",
        "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",
        "40", "41", "42", "43", "44", "45", "46", "47",
        "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
        "50", "51", "52", "53", "54", "55", "56", "57",
        "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
        "60", "61", "62", "63", "64", "65", "66", "67",
        "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
        "70", "71", "72", "73", "74", "75", "76", "77",
        "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
        "80", "81", "82", "83", "84", "85", "86", "87",
        "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
        "90", "91", "92", "93", "94", "95", "96", "97",
        "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
        "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7",
        "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
        "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7",
        "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
        "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7",
        "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
        "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
        "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
        "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7",
        "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
        "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7",
        "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"
};


/**
 *  General purpose utility methods.
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


/**
 * Returns the value of the parameter if defined or the String "(not
 * defined)"
 */
static const char *is_str_defined(const char *s) {
        return((s && *s) ? s : "(not defined)");
}


/**
 * Convert a hex char to a char
 */
static char _x2c(char *hex) {
        register char digit;
        digit = ((hex[0] >= 'A') ? ((hex[0] & 0xdf) - 'A')+10 : (hex[0] - '0'));
        digit *= 16;
        digit += (hex[1] >= 'A' ? ((hex[1] & 0xdf) - 'A')+10 : (hex[1] - '0'));
        return(digit);
}


/**
 * Print registered events list
 */
static void printevents(unsigned int events) {
        if (events == Event_Null) {
                printf("No events");
        } else if (events == Event_All) {
                printf("All events");
        } else {
                if (IS_EVENT_SET(events, Event_Action))
                        printf("Action ");
                if (IS_EVENT_SET(events, Event_ByteIn))
                        printf("ByteIn ");
                if (IS_EVENT_SET(events, Event_ByteOut))
                        printf("ByteOut ");
                if (IS_EVENT_SET(events, Event_Checksum))
                        printf("Checksum ");
                if (IS_EVENT_SET(events, Event_Connection))
                        printf("Connection ");
                if (IS_EVENT_SET(events, Event_Content))
                        printf("Content ");
                if (IS_EVENT_SET(events, Event_Data))
                        printf("Data ");
                if (IS_EVENT_SET(events, Event_Exec))
                        printf("Exec ");
                if (IS_EVENT_SET(events, Event_Exist))
                        printf("Exist ");
                if (IS_EVENT_SET(events, Event_FsFlag))
                        printf("Fsflags ");
                if (IS_EVENT_SET(events, Event_Gid))
                        printf("Gid ");
                if (IS_EVENT_SET(events, Event_Icmp))
                        printf("Icmp ");
                if (IS_EVENT_SET(events, Event_Instance))
                        printf("Instance ");
                if (IS_EVENT_SET(events, Event_Invalid))
                        printf("Invalid ");
                if (IS_EVENT_SET(events, Event_Link))
                        printf("Link ");
                if (IS_EVENT_SET(events, Event_NonExist))
                        printf("Nonexist ");
                if (IS_EVENT_SET(events, Event_PacketIn))
                        printf("PacketIn ");
                if (IS_EVENT_SET(events, Event_PacketOut))
                        printf("PacketOut ");
                if (IS_EVENT_SET(events, Event_Permission))
                        printf("Permission ");
                if (IS_EVENT_SET(events, Event_Pid))
                        printf("PID ");
                if (IS_EVENT_SET(events, Event_PPid))
                        printf("PPID ");
                if (IS_EVENT_SET(events, Event_Resource))
                        printf("Resource ");
                if (IS_EVENT_SET(events, Event_Saturation))
                        printf("Saturation ");
                if (IS_EVENT_SET(events, Event_Size))
                        printf("Size ");
                if (IS_EVENT_SET(events, Event_Speed))
                        printf("Speed ");
                if (IS_EVENT_SET(events, Event_Status))
                        printf("Status ");
                if (IS_EVENT_SET(events, Event_Timeout))
                        printf("Timeout ");
                if (IS_EVENT_SET(events, Event_Timestamp))
                        printf("Timestamp ");
                if (IS_EVENT_SET(events, Event_Uid))
                        printf("Uid ");
                if (IS_EVENT_SET(events, Event_Uptime))
                        printf("Uptime ");

        }
        printf("\n");
}


#ifdef HAVE_LIBPAM
/**
 * PAM conversation
 */
#if defined(SOLARIS) || defined(AIX)
static int PAMquery(int num_msg, struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
#else
static int PAMquery(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
#endif
        int i;
        struct ad_user *user = (struct ad_user *)appdata_ptr;
        struct pam_response *response;

        /* Sanity checking */
        if (! msg || ! resp || ! user )
                return PAM_CONV_ERR;

        response = CALLOC(sizeof(struct pam_response), num_msg);

        for (i = 0; i < num_msg; i++) {
                response[i].resp = NULL;
                response[i].resp_retcode = 0;

                switch ((*(msg[i])).msg_style) {
                        case PAM_PROMPT_ECHO_ON:
                                /* Store the login as the response. This likely never gets called, since login was on pam_start() */
                                response[i].resp = appdata_ptr ? Str_dup(user->login) : NULL;
                                break;

                        case PAM_PROMPT_ECHO_OFF:
                                /* Store the password as the response */
                                response[i].resp = appdata_ptr ? Str_dup(user->passwd) : NULL;
                                break;

                        case PAM_TEXT_INFO:
                        case PAM_ERROR_MSG:
                                /* Shouldn't happen since we have PAM_SILENT set. If it happens anyway, ignore it. */
                                break;

                        default:
                                /* Something strange... */
                                FREE(response);
                                return PAM_CONV_ERR;
                }
        }
        /* On success, return the response structure */
        *resp = response;
        return PAM_SUCCESS;
}


/**
 * Validate login/passwd via PAM service "monit"
 */
static bool PAMcheckPasswd(const char *login, const char *passwd) {
        int rv;
        pam_handle_t *pamh = NULL;
        struct ad_user user_info = {
                login,
                passwd
        };
        struct pam_conv conv = {
                PAMquery,
                &user_info
        };

        if ((rv = pam_start("monit", login, &conv, &pamh) != PAM_SUCCESS)) {
                DEBUG("PAM authentication start failed -- %d\n", rv);
                return false;
        }

        rv = pam_authenticate(pamh, PAM_SILENT);

        if (pam_end(pamh, rv) != PAM_SUCCESS)
                pamh = NULL;

        return rv == PAM_SUCCESS ? true : false;
}


/**
 * Check whether the user is member of allowed groups
 */
static Auth_T PAMcheckUserGroup(const char *uname) {
        Auth_T c = Run.httpd.credentials;
        struct passwd *pwd = NULL;
        struct group  *grp = NULL;

        ASSERT(uname);

        if (! (pwd = getpwnam(uname)))
                return NULL;

        if (! (grp = getgrgid(pwd->pw_gid)))
                return NULL;

        while (c) {
                if (c->groupname) {
                        struct group *sgrp = NULL;

                        /* check for primary group match */
                        if (IS(c->groupname, grp->gr_name))
                                return c;

                        /* check secondary groups match */
                        if ((sgrp = getgrnam(c->groupname))) {
                                char **g = NULL;

                                for (g = sgrp->gr_mem; *g; g++)
                                        if (IS(*g, uname))
                                                return c;
                        }
                }
                c = c->next;
        }
        return NULL;
}
#endif


/* ------------------------------------------------------------------ Public */


char *Util_replaceString(char **src, const char *old, const char *new) {
        ASSERT(src);
        ASSERT(*src);
        ASSERT(old);
        ASSERT(new);

        int i = Util_countWords(*src, old);
        if (i) {
                size_t l = strlen(old);
                size_t d = strlen(new) - l;
                if (d > 0) {
                        d *= i;
                } else {
                        d = 0;
                }
                char *buf = CALLOC(sizeof(char), strlen(*src) + d + 1);
                char *p;
                char *q = *src;
                *buf = 0;
                while ((p = strstr(q, old))) {
                        *p = 0;
                        strcat(buf, q);
                        strcat(buf, new);
                        p += l;
                        q = p;
                }
                strcat(buf, q);
                FREE(*src);
                *src = buf;
        }
        return *src;
}


int Util_countWords(char *s, const char *word) {
        int i = 0;
        char *p = s;

        ASSERT(s && word);

        while ((p = strstr(p, word))) { i++;  p++; }
        return i;
}


void Util_handleEscapes(char *buf) {
        int editpos;
        int insertpos;

        ASSERT(buf);

        for (editpos = insertpos = 0; *(buf + editpos) != '\0'; editpos++, insertpos++) {
                if (*(buf + editpos) == '\\' ) {
                        switch (*(buf + editpos + 1)) {
                                case 'n':
                                        *(buf + insertpos) = '\n';
                                        editpos++;
                                        break;

                                case 't':
                                        *(buf + insertpos) = '\t';
                                        editpos++;
                                        break;

                                case 'r':
                                        *(buf + insertpos) = '\r';
                                        editpos++;
                                        break;

                                case ' ':
                                        *(buf + insertpos) = ' ';
                                        editpos++;
                                        break;

                                case '0':
                                        if (*(buf + editpos+2) == 'x') {
                                                if ((*(buf + editpos + 3) == '0' && *(buf + editpos + 4) == '0')) {
                                                        /* Don't swap \0x00 with 0 to avoid truncating the string.
                                                         Currently the only place where we support sending of 0 bytes
                                                         is in check_generic(). The \0x00 -> 0 byte swap is performed
                                                         there and in-place.
                                                         */
                                                        *(buf + insertpos) = *(buf+editpos);
                                                } else {
                                                        *(buf + insertpos) = _x2c(&buf[editpos + 3]);
                                                        editpos += 4;
                                                }
                                        }
                                        break;

                                case '\\':
                                        *(buf + insertpos) = '\\';
                                        editpos++;
                                        break;

                                default:
                                        *(buf + insertpos) = *(buf + editpos);

                        }

                } else {
                        *(buf + insertpos) = *(buf + editpos);
                }

        }
        *(buf + insertpos) = '\0';
}


int Util_handle0Escapes(char *buf) {
        int editpos;
        int insertpos;

        ASSERT(buf);

        for (editpos = insertpos = 0; *(buf + editpos) != '\0'; editpos++, insertpos++) {
                if (*(buf + editpos) == '\\' ) {
                        switch (*(buf + editpos + 1)) {
                                case '0':
                                        if (*(buf + editpos + 2) == 'x') {
                                                *(buf + insertpos) = _x2c(&buf[editpos+3]);
                                                editpos += 4;
                                        }
                                        break;

                                default:
                                        *(buf + insertpos) = *(buf + editpos);

                        }

                } else {
                        *(buf + insertpos) = *(buf + editpos);
                }
        }
        *(buf + insertpos) = '\0';
        return insertpos;
}


Service_T Util_getService(const char *name) {
        ASSERT(name);
        for (Service_T s = servicelist; s; s = s->next)
                if (IS(s->name, name))
                        return s;
        return NULL;
}


int Util_getNumberOfServices() {
        int i = 0;
        Service_T s;
        for (s = servicelist; s; s = s->next)
                i += 1;
        return i;
}


bool Util_existService(const char *name) {
        ASSERT(name);
        return Util_getService(name) ? true : false;
}


void Util_printRunList() {
        char buf[10];
        printf("Runtime constants:\n");
        printf(" %-18s = %s\n", "Control file", is_str_defined(Run.files.control));
        printf(" %-18s = %s\n", "Log file", is_str_defined(Run.files.log));
        printf(" %-18s = %s\n", "Pid file", is_str_defined(Run.files.pid));
        printf(" %-18s = %s\n", "Id file", is_str_defined(Run.files.id));
        printf(" %-18s = %s\n", "State file", is_str_defined(Run.files.state));
        printf(" %-18s = %s\n", "Debug", Run.debug ? "True" : "False");
        printf(" %-18s = %s\n", "Log", (Run.flags & Run_Log) ? "True" : "False");
        printf(" %-18s = %s\n", "Use syslog", (Run.flags & Run_UseSyslog) ? "True" : "False");
        printf(" %-18s = %s\n", "Is Daemon", (Run.flags & Run_Daemon) ? "True" : "False");
        printf(" %-18s = %s\n", "Use process engine", (Run.flags & Run_ProcessEngineEnabled) ? "True" : "False");
        printf(" %-18s = {\n", "Limits");
        printf(" %-18s =   programOutput:     %s\n", " ", Convert_bytes2str(Run.limits.programOutput, buf));
        printf(" %-18s =   sendExpectBuffer:  %s\n", " ", Convert_bytes2str(Run.limits.sendExpectBuffer, buf));
        printf(" %-18s =   fileContentBuffer: %s\n", " ", Convert_bytes2str(Run.limits.fileContentBuffer, buf));
        printf(" %-18s =   httpContentBuffer: %s\n", " ", Convert_bytes2str(Run.limits.httpContentBuffer, buf));
        printf(" %-18s =   networkTimeout:    %s\n", " ", Convert_time2str(Run.limits.networkTimeout, (char[11]){}));
        printf(" %-18s =   programTimeout:    %s\n", " ", Convert_time2str(Run.limits.programTimeout, (char[11]){}));
        printf(" %-18s =   stopTimeout:       %s\n", " ", Convert_time2str(Run.limits.stopTimeout, (char[11]){}));
        printf(" %-18s =   startTimeout:      %s\n", " ", Convert_time2str(Run.limits.startTimeout, (char[11]){}));
        printf(" %-18s =   restartTimeout:    %s\n", " ", Convert_time2str(Run.limits.restartTimeout, (char[11]){}));
        printf(" %-18s = }\n", " ");
        printf(" %-18s = %s\n", "On reboot", onrebootnames[Run.onreboot]);
        printf(" %-18s = %d seconds with start delay %d seconds\n", "Poll time", Run.polltime, Run.startdelay);

        if (Run.eventlist_dir) {
                char slots[STRLEN];

                if (Run.eventlist_slots < 0)
                        snprintf(slots, STRLEN, "unlimited");
                else
                        snprintf(slots, STRLEN, "%d", Run.eventlist_slots);

                printf(" %-18s = base directory %s with %s slots\n",
                       "Event queue", Run.eventlist_dir, slots);
        }
#ifdef HAVE_OPENSSL
        {
                const char *options = Ssl_printOptions(&(Run.ssl), (char[STRLEN]){}, STRLEN);
                if (options && *options)
                        printf(" %-18s = %s\n", "SSL options", options);
        }
#endif
        if (Run.mmonits) {
                Mmonit_T c;
                printf(" %-18s = ", "M/Monit(s)");
                for (c = Run.mmonits; c; c = c->next) {
                        printf("%s with timeout %s", c->url->url, Convert_time2str(c->timeout, (char[11]){}));
#ifdef HAVE_OPENSSL
                        if (c->ssl.flags) {
                                printf(" using TLS");
                                const char *options = Ssl_printOptions(&c->ssl, (char[STRLEN]){}, STRLEN);
                                if (options && *options)
                                        printf(" with options {%s}", options);
                                if (c->ssl.checksum)
                                        printf(" and certificate checksum %s equal to '%s'", checksumnames[c->ssl.checksumType], c->ssl.checksum);
                        }
#endif
                        if (Run.flags & Run_MmonitCredentials && c->url->user)
                                printf(" with credentials");
                        if (c->next)
                               printf(",\n                    = ");
                }
                printf("\n");
        }

        if (Run.mailservers) {
                MailServer_T mta;
                printf(" %-18s = ", "Mail server(s)");
                for (mta = Run.mailservers; mta; mta = mta->next) {
                        printf("%s:%d", mta->host, mta->port);
#ifdef HAVE_OPENSSL
                        if (mta->ssl.flags) {
                                printf(" using TLS");
                                const char *options = Ssl_printOptions(&mta->ssl, (char[STRLEN]){}, STRLEN);
                                if (options && *options)
                                        printf(" with options {%s}", options);
                                if (mta->ssl.checksum)
                                        printf(" and certificate checksum %s equal to '%s'", checksumnames[mta->ssl.checksumType], mta->ssl.checksum);
                        }
#endif
                        if (mta->next)
                                printf(", ");
                }
                printf(" with timeout %s", Convert_time2str(Run.mailserver_timeout, (char[11]){}));
                if (Run.mail_hostname)
                        printf(" using '%s' as my hostname", Run.mail_hostname);
                printf("\n");
        }

        if (Run.MailFormat.from) {
                if (Run.MailFormat.from->name)
                        printf(" %-18s = %s <%s>\n", "Mail from", Run.MailFormat.from->name, Run.MailFormat.from->address);
                else
                        printf(" %-18s = %s\n", "Mail from", Run.MailFormat.from->address);
        }
        if (Run.MailFormat.replyto) {
                if (Run.MailFormat.replyto->name)
                        printf(" %-18s = %s <%s>\n", "Mail reply to", Run.MailFormat.replyto->name, Run.MailFormat.replyto->address);
                else
                        printf(" %-18s = %s\n", "Mail reply to", Run.MailFormat.replyto->address);
        }
        if (Run.MailFormat.subject)
                printf(" %-18s = %s\n", "Mail subject", Run.MailFormat.subject);
        if (Run.MailFormat.message)
                printf(" %-18s = %-.20s..(truncated)\n", "Mail message", Run.MailFormat.message);

        printf(" %-18s = %s\n", "Start monit httpd", (Run.httpd.flags & Httpd_Net || Run.httpd.flags & Httpd_Unix) ? "True" : "False");

        if (Run.httpd.flags & Httpd_Net || Run.httpd.flags & Httpd_Unix) {
                if (Run.httpd.flags & Httpd_Net) {
                        printf(" %-18s = %s\n", "httpd bind address", Run.httpd.socket.net.address ? Run.httpd.socket.net.address : "Any/All");
                        printf(" %-18s = %d\n", "httpd portnumber", Run.httpd.socket.net.port);
                        printf(" %-18s = %s\n", "httpd net readonly", Run.httpd.socket.net.readonly ? "Enabled" : "Disabled");
#ifdef HAVE_OPENSSL
                        const char *options = Ssl_printOptions(&(Run.httpd.socket.net.ssl), (char[STRLEN]){}, STRLEN);
                        if (options && *options)
                                printf(" %-18s = %s\n", "httpd encryption", options);
#endif
                }
                if (Run.httpd.flags & Httpd_Unix) {
                        printf(" %-18s = %s\n", "httpd unix socket", Run.httpd.socket.unix.path);
                        printf(" %-18s = %s\n", "httpd unix readonly", Run.httpd.socket.unix.readonly ? "Enabled" : "Disabled");
                }
                printf(" %-18s = %s\n", "httpd signature", Run.httpd.flags & Httpd_Signature ? "Enabled" : "Disabled");
                printf(" %-18s = %s\n", "httpd auth. style",
                       Run.httpd.credentials && Engine_hasAllow() ? "Basic Authentication and Host/Net allow list" : Run.httpd.credentials ? "Basic Authentication" : Engine_hasAllow() ? "Host/Net allow list" : "No authentication!");

        }

        {
                for (Mail_T list = Run.maillist; list; list = list->next) {
                        printf(" %-18s = %s\n", "Alert mail to", is_str_defined(list->to));
                        printf("   %-16s = ", "Alert on");
                        printevents(list->events);
                        if (list->reminder)
                                printf("   %-16s = %u cycles\n", "Alert reminder", list->reminder);
                }
        }

        printf("\n");
}


void Util_printService(Service_T s) {
        ASSERT(s);

        bool sgheader = false;
        char buffer[STRLEN];
        StringBuffer_T buf = StringBuffer_create(STRLEN);

        printf("%-21s = %s\n", StringBuffer_toString(StringBuffer_append(buf, "%s Name", servicetypes[s->type])), s->name);

        for (ServiceGroup_T o = servicegrouplist; o; o = o->next) {
                for (list_t m = o->members->head; m; m = m->next) {
                        if (m->e == s) {
                                if (! sgheader) {
                                        printf(" %-20s = %s", "Group", o->name);
                                        sgheader = true;
                                } else {
                                        printf(", %s", o->name);
                                }
                        }
                }
        }
        if (sgheader)
                printf("\n");

        if (s->type == Service_Process) {
                if (s->matchlist)
                        printf(" %-20s = %s\n", "Match", s->path);
                else
                        printf(" %-20s = %s\n", "Pid file", s->path);
        } else if (s->type == Service_Host) {
                printf(" %-20s = %s\n", "Address", s->path);
        } else if (s->type == Service_Net) {
                printf(" %-20s = %s\n", "Interface", s->path);
        } else if (s->type != Service_System) {
                printf(" %-20s = %s\n", "Path", s->path);
        }
        printf(" %-20s = %s\n", "Monitoring mode", modenames[s->mode]);
        printf(" %-20s = %s\n", "On reboot", onrebootnames[s->onreboot]);
        if (s->start) {
                printf(" %-20s = '%s'", "Start program", Util_commandDescription(s->start, (char[STRLEN]){}));
                if (s->start->has_uid)
                        printf(" as uid %d", s->start->uid);
                if (s->start->has_gid)
                        printf(" as gid %d", s->start->gid);
                printf(" timeout %s", Convert_time2str(s->start->timeout, (char[11]){}));
                printf("\n");
        }
        if (s->stop) {
                printf(" %-20s = '%s'", "Stop program", Util_commandDescription(s->stop, (char[STRLEN]){}));
                if (s->stop->has_uid)
                        printf(" as uid %d", s->stop->uid);
                if (s->stop->has_gid)
                        printf(" as gid %d", s->stop->gid);
                printf(" timeout %s", Convert_time2str(s->stop->timeout, (char[11]){}));
                printf("\n");
        }
        if (s->restart) {
                printf(" %-20s = '%s'", "Restart program", Util_commandDescription(s->restart, (char[STRLEN]){}));
                if (s->restart->has_uid)
                        printf(" as uid %d", s->restart->uid);
                if (s->restart->has_gid)
                        printf(" as gid %d", s->restart->gid);
                printf(" timeout %s", Convert_time2str(s->restart->timeout, (char[11]){}));
                printf("\n");
        }

        for (NonExist_T o = s->nonexistlist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Existence", StringBuffer_toString(Util_printRule(false, buf, o->action, "if does not exist")));
        }

        for (Exist_T o = s->existlist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Non-Existence", StringBuffer_toString(Util_printRule(false, buf, o->action, "if exist")));
        }

        for (Dependant_T o = s->dependantlist; o; o = o->next)
                if (o->dependant != NULL)
                        printf(" %-20s = %s\n", "Depends on Service", o->dependant);

        for (Pid_T o = s->pidlist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Pid", StringBuffer_toString(Util_printRule(false, buf, o->action, "if changed")));
        }

        for (Pid_T o = s->ppidlist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "PPid", StringBuffer_toString(Util_printRule(false, buf, o->action, "if changed")));
        }

        for (FsFlag_T o = s->fsflaglist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Filesystem flags", StringBuffer_toString(Util_printRule(false, buf, o->action, "if changed")));
        }

        if (s->type == Service_Program) {
                printf(" %-20s = ", "Program timeout");
                printf("terminate the program if not finished within %s\n", Convert_time2str(s->program->timeout, (char[11]){}));
                for (Status_T o = s->statuslist; o; o = o->next) {
                        StringBuffer_clear(buf);
                        if (o->operator == Operator_Changed)
                                printf(" %-20s = %s\n", "Status", StringBuffer_toString(Util_printRule(false, buf, o->action, "if exit value changed")));
                        else
                                printf(" %-20s = %s\n", "Status", StringBuffer_toString(Util_printRule(false, buf, o->action, "if exit value %s %d", operatorshortnames[o->operator], o->return_value)));
                }
        }

        if (s->checksum && s->checksum->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Checksum",
                       s->checksum->test_changes
                       ?
                       StringBuffer_toString(Util_printRule(false, buf, s->checksum->action, "if changed %s", checksumnames[s->checksum->type]))
                       :
                       StringBuffer_toString(Util_printRule(false, buf, s->checksum->action, "if failed %s(%s)", s->checksum->hash, checksumnames[s->checksum->type]))
                       );
        }

        if (s->perm && s->perm->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Permission",
                       s->perm->test_changes
                       ?
                       StringBuffer_toString(Util_printRule(false, buf, s->perm->action, "if changed"))
                       :
                       StringBuffer_toString(Util_printRule(false, buf, s->perm->action, "if failed %04o", s->perm->perm))
                       );
        }

        if (s->uid && s->uid->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "UID", StringBuffer_toString(Util_printRule(false, buf, s->uid->action, "if failed %d", s->uid->uid)));
        }

        if (s->euid && s->euid->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "EUID", StringBuffer_toString(Util_printRule(false, buf, s->euid->action, "if failed %d", s->euid->uid)));
        }

        for (SecurityAttribute_T o = s->secattrlist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Security attribute", StringBuffer_toString(Util_printRule(false, buf, o->action, "if failed %s", o->attribute)));
        }

        for (Filedescriptors_T o = s->filedescriptorslist; o; o = o->next) {
                StringBuffer_clear(buf);
                if (o->total) {
                        printf(" %-20s = %s\n", "Total filedescriptors", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %lld", operatornames[o->operator], o->limit_absolute)));
                } else {
                        if (o->limit_absolute > -1)
                                printf(" %-20s = %s\n", "Filedescriptors", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %lld", operatornames[o->operator], o->limit_absolute)));
                        else
                                printf(" %-20s = %s\n", "Filedescriptors", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit_percent)));
                }
        }

        if (s->gid && s->gid->action) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "GID", StringBuffer_toString(Util_printRule(false, buf, s->gid->action, "if failed %d", s->gid->gid)));
        }

        for (Icmp_T o = s->icmplist; o; o = o->next) {
                StringBuffer_clear(buf);
                StringBuffer_T buf2 = StringBuffer_create(64);
                StringBuffer_append(buf2, "if %s count %d size %d with timeout %s", o->check_invers ? "succeeded" : "failed", o->count, o->size, Convert_time2str(o->timeout, (char[11]){}));
                if (o->responsetime.limit > -1.)
                        StringBuffer_append(buf2, " and responsetime %s %s", operatornames[o->responsetime.operator], Convert_time2str(o->responsetime.limit, (char[11]){}));
                if (o->outgoing.ip)
                        StringBuffer_append(buf2, " via address %s",  o->outgoing.ip);
                switch (o->family) {
                        case Socket_Ip4:
                                printf(" %-20s = %s\n", "Ping4", StringBuffer_toString(Util_printRule(o->check_invers, buf, o->action, "%s", StringBuffer_toString(buf2))));
                                break;
                        case Socket_Ip6:
                                printf(" %-20s = %s\n", "Ping6", StringBuffer_toString(Util_printRule(o->check_invers, buf, o->action, "%s", StringBuffer_toString(buf2))));
                                break;
                        default:
                                printf(" %-20s = %s\n", "Ping", StringBuffer_toString(Util_printRule(o->check_invers, buf, o->action, "%s", StringBuffer_toString(buf2))));
                                break;
                }
                StringBuffer_free(&buf2);
        }

        for (Port_T o = s->portlist; o; o = o->next) {
                StringBuffer_clear(buf);
                StringBuffer_T buf2 = StringBuffer_create(64);
                StringBuffer_append(buf2, "if %s [%s]:%d%s",
                        o->check_invers ? "succeeded" : "failed", o->hostname, o->target.net.port, Util_portRequestDescription(o));
                if (o->outgoing.ip)
                        StringBuffer_append(buf2, " via address %s", o->outgoing.ip);
                StringBuffer_append(buf2, " type %s/%s protocol %s with timeout %s",
                        Util_portTypeDescription(o), Util_portIpDescription(o), o->protocol->name, Convert_time2str(o->timeout, (char[11]){}));
                if (o->retry > 1)
                        StringBuffer_append(buf2, " and retry %d times", o->retry);
                if (o->responsetime.limit > -1.)
                        StringBuffer_append(buf2, " and responsetime %s %s", operatornames[o->responsetime.operator], Convert_time2str(o->responsetime.limit, (char[11]){}));
#ifdef HAVE_OPENSSL
                if (o->target.net.ssl.options.flags) {
                        StringBuffer_append(buf2, " using TLS");
                        const char *options = Ssl_printOptions(&o->target.net.ssl.options, (char[STRLEN]){}, STRLEN);
                        if (options && *options)
                                StringBuffer_append(buf2, " with options {%s}", options);
                        if (o->target.net.ssl.certificate.minimumDays > 0)
                                StringBuffer_append(buf2, " and certificate valid for at least %d days", o->target.net.ssl.certificate.minimumDays);
                        if (o->target.net.ssl.options.checksum)
                                StringBuffer_append(buf2, " and certificate checksum %s equal to '%s'", checksumnames[o->target.net.ssl.options.checksumType], o->target.net.ssl.options.checksum);
                }
#endif
                printf(" %-20s = %s\n", "Port", StringBuffer_toString(Util_printRule(o->check_invers, buf, o->action, "%s", StringBuffer_toString(buf2))));
                StringBuffer_free(&buf2);
        }

        for (Port_T o = s->socketlist; o; o = o->next) {
                StringBuffer_clear(buf);
                StringBuffer_T buf2 = StringBuffer_create(64);
                StringBuffer_append(buf2, "if %s %s type %s protocol %s with timeout %s", o->check_invers ? "succeeded" : "failed", o->target.unix.pathname, Util_portTypeDescription(o), o->protocol->name, Convert_time2str(o->timeout, (char[11]){}));
                if (o->retry > 1)
                        StringBuffer_append(buf2, " and retry %d times", o->retry);
                if (o->responsetime.limit > -1.)
                        StringBuffer_append(buf2, " and responsetime %s %s", operatornames[o->responsetime.operator], Convert_time2str(o->responsetime.limit, (char[11]){}));
                printf(" %-20s = %s\n", "Unix Socket", StringBuffer_toString(Util_printRule(o->check_invers, buf, o->action, "%s", StringBuffer_toString(buf2))));
                StringBuffer_free(&buf2);
        }

        for (Timestamp_T o = s->timestamplist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", timestampnames[o->type],
                       o->test_changes
                       ?
                       StringBuffer_toString(Util_printRule(false, buf, o->action, "if changed"))
                       :
                       StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s", operatornames[o->operator], Convert_time2str(o->time * 1000., (char[11]){})))
                       );
        }

        for (Size_T o = s->sizelist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Size",
                       o->test_changes
                       ?
                       StringBuffer_toString(Util_printRule(false, buf, o->action, "if changed"))
                       :
                       StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %llu byte(s)", operatornames[o->operator], o->size))
                       );
        }

        for (LinkStatus_T o = s->linkstatuslist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Link status", StringBuffer_toString(Util_printRule(o->check_invers, buf, o->action, "if %s", o->check_invers ? "up" : "down")));
        }

        for (LinkSpeed_T o = s->linkspeedlist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Link capacity", StringBuffer_toString(Util_printRule(false, buf, o->action, "if changed")));
        }

        for (LinkSaturation_T o = s->linksaturationlist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Link utilization", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit)));
        }

        for (Bandwidth_T o = s->uploadbyteslist; o; o = o->next) {
                StringBuffer_clear(buf);
                if (o->range == Time_Second) {
                        printf(" %-20s = %s\n", "Upload bytes", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s/s", operatornames[o->operator], Convert_bytes2str(o->limit, buffer))));
                } else {
                        printf(" %-20s = %s\n", "Total upload bytes", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s in last %d %s(s)", operatornames[o->operator], Convert_bytes2str(o->limit, buffer), o->rangecount, Util_timestr(o->range))));
                }
        }

        for (Bandwidth_T o = s->uploadpacketslist; o; o = o->next) {
                StringBuffer_clear(buf);
                if (o->range == Time_Second) {
                        printf(" %-20s = %s\n", "Upload packets", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %lld packets/s", operatornames[o->operator], o->limit)));
                } else {
                        printf(" %-20s = %s\n", "Total upload packets", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %lld packets in last %d %s(s)", operatornames[o->operator], o->limit, o->rangecount, Util_timestr(o->range))));
                }
        }

        for (Bandwidth_T o = s->downloadbyteslist; o; o = o->next) {
                StringBuffer_clear(buf);
                if (o->range == Time_Second) {
                        printf(" %-20s = %s\n", "Download bytes", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s/s", operatornames[o->operator], Convert_bytes2str(o->limit, buffer))));
                } else {
                        printf(" %-20s = %s\n", "Total download bytes", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s in last %d %s(s)", operatornames[o->operator], Convert_bytes2str(o->limit, buffer), o->rangecount, Util_timestr(o->range))));
                }
        }

        for (Bandwidth_T o = s->downloadpacketslist; o; o = o->next) {
                StringBuffer_clear(buf);
                if (o->range == Time_Second) {
                        printf(" %-20s = %s\n", "Download packets", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %lld packets/s", operatornames[o->operator], o->limit)));
                } else {
                        printf(" %-20s = %s\n", "Total downl. packets", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %lld packets in last %d %s(s)", operatornames[o->operator], o->limit, o->rangecount, Util_timestr(o->range))));
                }
        }

        for (Uptime_T o = s->uptimelist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = %s\n", "Uptime", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %llu second(s)", operatornames[o->operator], o->uptime)));
        }

        if (s->type != Service_Process) {
                for (Match_T o = s->matchignorelist; o; o = o->next) {
                        StringBuffer_clear(buf);
                        printf(" %-20s = %s\n", "Ignore content", StringBuffer_toString(Util_printRule(false, buf, o->action, "if content %s \"%s\"", o->not ? "!=" : "=", o->match_string)));
                }
                for (Match_T o = s->matchlist; o; o = o->next) {
                        StringBuffer_clear(buf);
                        printf(" %-20s = %s\n", "Content", StringBuffer_toString(Util_printRule(false, buf, o->action, "if content %s \"%s\"", o->not ? "!=" : "=", o->match_string)));
                }
        }

        for (FileSystem_T o = s->filesystemlist; o; o = o->next) {
                StringBuffer_clear(buf);
                if (o->resource == Resource_Inode) {
                        printf(" %-20s = %s\n", "Inodes usage limit",
                               o->limit_absolute > -1
                               ?
                               StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %lld", operatornames[o->operator], o->limit_absolute))
                               :
                               StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit_percent))
                               );
                } else if (o->resource == Resource_InodeFree) {
                        printf(" %-20s = %s\n", "Inodes free limit",
                               o->limit_absolute > -1
                               ?
                               StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %lld", operatornames[o->operator], o->limit_absolute))
                               :
                               StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit_percent))
                               );
                } else if (o->resource == Resource_Space) {
                        if (o->limit_absolute > -1) {
                                printf(" %-20s = %s\n", "Space usage limit", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s", operatornames[o->operator], Convert_bytes2str(o->limit_absolute, buffer))));
                        } else {
                               printf(" %-20s = %s\n", "Space usage limit", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit_percent)));
                        }
                } else if (o->resource == Resource_SpaceFree) {
                        if (o->limit_absolute > -1) {
                                printf(" %-20s = %s\n", "Space free limit", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s", operatornames[o->operator], Convert_bytes2str(o->limit_absolute, buffer))));
                        } else {
                               printf(" %-20s = %s\n", "Space free limit", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit_percent)));
                        }
                } else if (o->resource == Resource_ReadBytes) {
                        printf(" %-20s = %s\n", "Read limit", StringBuffer_toString(Util_printRule(false, buf, o->action, "if read %s %s/s", operatornames[o->operator], Convert_bytes2str(o->limit_absolute, (char[10]){}))));
                } else if (o->resource == Resource_ReadOperations) {
                        printf(" %-20s = %s\n", "Read limit", StringBuffer_toString(Util_printRule(false, buf, o->action, "if read %s %llu operations/s", operatornames[o->operator], o->limit_absolute)));
                } else if (o->resource == Resource_WriteBytes) {
                        printf(" %-20s = %s\n", "Write limit", StringBuffer_toString(Util_printRule(false, buf, o->action, "if write %s %s/s", operatornames[o->operator], Convert_bytes2str(o->limit_absolute, (char[10]){}))));
                } else if (o->resource == Resource_WriteOperations) {
                        printf(" %-20s = %s\n", "Write limit", StringBuffer_toString(Util_printRule(false, buf, o->action, "if write %s %llu operations/s", operatornames[o->operator], o->limit_absolute)));
                } else if (o->resource == Resource_ServiceTime) {
                        printf(" %-20s = %s\n", "Service time limit", StringBuffer_toString(Util_printRule(false, buf, o->action, "if service time %s %s/operation", operatornames[o->operator], Convert_time2str(o->limit_absolute, (char[11]){}))));
                }
        }

        for (Resource_T o = s->resourcelist; o; o = o->next) {
                StringBuffer_clear(buf);
                switch (o->resource_id) {
                        case Resource_CpuPercent:
                                printf(" %-20s = ", "CPU usage limit");
                                break;

                        case Resource_CpuPercentTotal:
                                printf(" %-20s = ", "CPU usage limit (incl. children)");
                                break;

                        case Resource_CpuUser:
                                printf(" %-20s = ", "CPU user limit");
                                break;

                        case Resource_CpuSystem:
                                printf(" %-20s = ", "CPU system limit");
                                break;

                        case Resource_CpuWait:
                                printf(" %-20s = ", "CPU I/O wait limit");
                                break;

                        case Resource_CpuNice:
                                printf(" %-20s = ", "CPU nice limit");
                                break;

                        case Resource_CpuHardIRQ:
                                printf(" %-20s = ", "CPU hardware IRQ limit");
                                break;

                        case Resource_CpuSoftIRQ:
                                printf(" %-20s = ", "CPU software IRQ limit");
                                break;

                        case Resource_CpuSteal:
                                printf(" %-20s = ", "CPU steal limit");
                                break;

                        case Resource_CpuGuest:
                                printf(" %-20s = ", "CPU guest limit");
                                break;

                        case Resource_CpuGuestNice:
                                printf(" %-20s = ", "CPU guest nice limit");
                                break;

                        case Resource_MemoryPercent:
                                printf(" %-20s = ", "Memory usage limit");
                                break;

                        case Resource_MemoryKbyte:
                                printf(" %-20s = ", "Memory amount limit");
                                break;

                        case Resource_SwapPercent:
                                printf(" %-20s = ", "Swap usage limit");
                                break;

                        case Resource_SwapKbyte:
                                printf(" %-20s = ", "Swap amount limit");
                                break;

                        case Resource_LoadAverage1m:
                                printf(" %-20s = ", "Load avg (1m)");
                                break;

                        case Resource_LoadAverage5m:
                                printf(" %-20s = ", "Load avg (5m)");
                                break;

                        case Resource_LoadAverage15m:
                                printf(" %-20s = ", "Load avg (15m)");
                                break;

                        case Resource_LoadAveragePerCore1m:
                                printf(" %-20s = ", "Load avg/core (1m)");
                                break;

                        case Resource_LoadAveragePerCore5m:
                                printf(" %-20s = ", "Load avg/core (5m)");
                                break;

                        case Resource_LoadAveragePerCore15m:
                                printf(" %-20s = ", "Load avg/core (15m)");
                                break;

                        case Resource_Threads:
                                printf(" %-20s = ", "Threads");
                                break;

                        case Resource_Children:
                                printf(" %-20s = ", "Children");
                                break;

                        case Resource_MemoryKbyteTotal:
                                printf(" %-20s = ", "Memory amount limit (incl. children)");
                                break;

                        case Resource_MemoryPercentTotal:
                                printf(" %-20s = ", "Memory usage limit (incl. children)");
                                break;

                        case Resource_ReadBytes:
                                printf(" %-20s = ", "Read limit");
                                break;

                        case Resource_ReadBytesPhysical:
                                printf(" %-20s = ", "Disk read limit");
                                break;

                        case Resource_ReadOperations:
                                printf(" %-20s = ", "Disk read limit");
                                break;

                        case Resource_WriteBytes:
                                printf(" %-20s = ", "Write limit");
                                break;

                        case Resource_WriteBytesPhysical:
                                printf(" %-20s = ", "Disk write limit");
                                break;

                        case Resource_WriteOperations:
                                printf(" %-20s = ", "Disk write limit");
                                break;

                        default:
                                break;
                }
                switch (o->resource_id) {
                        case Resource_CpuPercent:
                        case Resource_CpuPercentTotal:
                        case Resource_MemoryPercentTotal:
                        case Resource_CpuUser:
                        case Resource_CpuSystem:
                        case Resource_CpuWait:
                        case Resource_CpuNice:
                        case Resource_CpuHardIRQ:
                        case Resource_CpuSoftIRQ:
                        case Resource_CpuSteal:
                        case Resource_CpuGuest:
                        case Resource_CpuGuestNice:
                        case Resource_MemoryPercent:
                        case Resource_SwapPercent:
                                printf("%s", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.1f%%", operatornames[o->operator], o->limit)));
                                break;

                        case Resource_MemoryKbyte:
                        case Resource_SwapKbyte:
                        case Resource_MemoryKbyteTotal:
                                printf("%s", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s", operatornames[o->operator], Convert_bytes2str(o->limit, buffer))));
                                break;

                        case Resource_LoadAverage1m:
                        case Resource_LoadAverage5m:
                        case Resource_LoadAverage15m:
                        case Resource_LoadAveragePerCore1m:
                        case Resource_LoadAveragePerCore5m:
                        case Resource_LoadAveragePerCore15m:
                                printf("%s", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.1f", operatornames[o->operator], o->limit)));
                                break;

                        case Resource_Threads:
                        case Resource_Children:
                                printf("%s", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.0f", operatornames[o->operator], o->limit)));
                                break;

                        case Resource_ReadBytes:
                        case Resource_WriteBytes:
                                printf("%s", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s/s", operatornames[o->operator], Convert_bytes2str(o->limit, (char[10]){}))));
                                break;

                        case Resource_ReadBytesPhysical:
                        case Resource_WriteBytesPhysical:
                                printf("%s", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %s/s", operatornames[o->operator], Convert_bytes2str(o->limit, (char[10]){}))));
                                break;

                        case Resource_ReadOperations:
                        case Resource_WriteOperations:
                                printf("%s", StringBuffer_toString(Util_printRule(false, buf, o->action, "if %s %.0f operations/s", operatornames[o->operator], o->limit)));
                                break;

                        default:
                                break;
                }
                printf("\n");
        }

        if (s->every.type == Every_SkipCycles)
                printf(" %-20s = Check service every %d cycles\n", "Every", s->every.spec.cycle.number);
        else if (s->every.type == Every_Cron)
                printf(" %-20s = Check service every %s\n", "Every", s->every.spec.cron);
        else if (s->every.type == Every_NotInCron)
                printf(" %-20s = Don't check service every %s\n", "Every", s->every.spec.cron);

        for (ActionRate_T o = s->actionratelist; o; o = o->next) {
                StringBuffer_clear(buf);
                printf(" %-20s = If restarted %d times within %d cycle(s) then %s\n", "Timeout", o->count, o->cycle, StringBuffer_toString(Util_printAction(o->action->failed, buf)));
        }

        for (Mail_T o = s->maillist; o; o = o->next) {
                printf(" %-20s = %s\n", "Alert mail to", is_str_defined(o->to));
                printf("   %-18s = ", "Alert on");
                printevents(o->events);
                if (o->reminder)
                        printf("   %-18s = %u cycles\n", "Alert reminder", o->reminder);
        }

        printf("\n");

        StringBuffer_free(&buf);
}


void Util_printServiceList() {
        Service_T s;
        char ruler[STRLEN];

        printf("The service list contains the following entries:\n\n");

        for (s = servicelist_conf; s; s = s->next_conf)
                Util_printService(s);

        memset(ruler, '-', STRLEN);
        printf("%-.79s\n", ruler);
}


char *Util_getToken(MD_T token) {
        md5_context_t ctx;
        char buf[STRLEN] = {};
        MD_T digest;
        System_random(buf, sizeof(buf));
        md5_init(&ctx);
        md5_append(&ctx, (const md5_byte_t *)buf, STRLEN - 1);
        md5_finish(&ctx, (md5_byte_t *)digest);
        Checksum_digest2Bytes((unsigned char *)digest, 16, token);
        return token;
}


char *Util_monitId(char *idfile) {
        ASSERT(idfile);
        FILE *file = NULL;
        if (! File_exist(idfile)) {
                // Generate the unique id
                file = fopen(idfile, "w");
                if (! file) {
                        Log_error("Error opening the idfile '%s' -- %s\n", idfile, STRERROR);
                        return NULL;
                }
                fprintf(file, "%s", Util_getToken(Run.id));
                Log_info(" New Monit id: %s\n Stored in '%s'\n", Run.id, idfile);
        } else {
                if (! File_isFile(idfile)) {
                        Log_error("idfile '%s' is not a regular file\n", idfile);
                        return NULL;
                }
                if ((file = fopen(idfile,"r")) == (FILE *)NULL) {
                        Log_error("Error opening the idfile '%s' -- %s\n", idfile, STRERROR);
                        return NULL;
                }
                if (fscanf(file, "%64s", Run.id) != 1) {
                        Log_error("Error reading id from file '%s'\n", idfile);
                        if (fclose(file))
                                Log_error("Error closing file '%s' -- %s\n", idfile, STRERROR);
                        return NULL;
                }
        }
        if (fclose(file))
                Log_error("Error closing file '%s' -- %s\n", idfile, STRERROR);

        return Run.id;
}


pid_t Util_getPid(char *pidfile) {
        FILE *file = NULL;
        int pid = -1;

        ASSERT(pidfile);

        if (! File_exist(pidfile)) {
                DEBUG("pidfile '%s' does not exist\n", pidfile);
                return 0;
        }
        if (! File_isFile(pidfile)) {
                DEBUG("pidfile '%s' is not a regular file\n", pidfile);
                return 0;
        }
        if ((file = fopen(pidfile,"r")) == (FILE *)NULL) {
                DEBUG("Error opening the pidfile '%s' -- %s\n", pidfile, STRERROR);
                return 0;
        }
        if (fscanf(file, "%d", &pid) != 1) {
                DEBUG("Error reading pid from file '%s'\n", pidfile);
                if (fclose(file))
                        DEBUG("Error closing file '%s' -- %s\n", pidfile, STRERROR);
                return 0;
        }
        if (fclose(file))
                DEBUG("Error closing file '%s' -- %s\n", pidfile, STRERROR);

        if (pid < 0)
                return(0);

        return (pid_t)pid;

}


bool Util_isurlsafe(const char *url) {
        ASSERT(url && *url);
        for (int i = 0; url[i]; i++)
                if (urlunsafe[(unsigned char)url[i]])
                        return false;
        return true;
}


char *Util_urlEncode(const char *string, bool isParameterValue) {
        char *escaped = NULL;
        if (string) {
                char *p;
                int i, n;
                const unsigned char *unsafe = isParameterValue ? urlunsafeparameter : urlunsafe;
                for (n = i = 0; string[i]; i++)
                        if (unsafe[(unsigned char)(string[i])])
                                n += 2;
                p = escaped = ALLOC(i + n + 1);
                for (; *string; string++, p++) {
                        if (unsafe[(unsigned char)(*p = *string)]) {
                                *p++ = '%';
                                *p++ = b2x[(unsigned char)(*string)][0];
                                *p = b2x[(unsigned char)(*string)][1];
                        }
                }
                *p = 0;
        }
        return escaped;
}


char *Util_urlDecode(char *url) {
        if (url && *url) {
                register int x, y;
                for (x = 0, y = 0; url[y]; x++, y++) {
                        if (url[y] == '+') {
                                url[x] = ' ';
                        } else if (url[y] == '%') {
                                if (! url[y + 1] || ! url[y + 2])
                                        break;
                                url[x] = _x2c(url + y + 1);
                                y += 2;
                        } else {
                                url[x] = url[y];
                        }
                }
                url[x] = 0;
        }
        return url;
}


char *Util_getBasicAuthHeader(char *username, char *password) {
        char *auth, *b64;
        char  buf[STRLEN];

        if (! username)
                return NULL;

        snprintf(buf, STRLEN, "%s:%s", username, password ? password : "");
        if (! (b64 = encode_base64(strlen(buf), (unsigned char *)buf)) ) {
                Log_error("Failed to base64 encode authentication header\n");
                return NULL;
        }
        auth = CALLOC(sizeof(char), STRLEN + 1);
        snprintf(auth, STRLEN, "Authorization: Basic %s\r\n", b64);
        FREE(b64);
        return auth;
}


void Util_redirectStdFds() {
        for (int i = 0; i < 3; i++) {
                if (close(i) == -1 || open("/dev/null", O_RDWR) != i) {
                        Log_error("Cannot reopen standard file descriptor (%d) -- %s\n", i, STRERROR);
                }
        }
}


void Util_closeFds() {
        for (int i = 3, descriptors = System_getDescriptorsGuarded(); i < descriptors; i++) {
                close(i);
        }
        errno = 0;
}


Auth_T Util_getUserCredentials(char *uname) {
        /* check allowed user names */
        for (Auth_T c = Run.httpd.credentials; c; c = c->next)
                if (c->uname && IS(c->uname, uname))
                        return c;

#ifdef HAVE_LIBPAM
        /* check allowed group names */
        return(PAMcheckUserGroup(uname));
#else
        return NULL;
#endif
}


bool Util_checkCredentials(char *uname, char *outside) {
        Auth_T c = Util_getUserCredentials(uname);
        char outside_crypt[STRLEN];
        if (c == NULL)
                return false;
        switch (c->digesttype) {
                case Digest_Cleartext:
                        outside_crypt[sizeof(outside_crypt) - 1] = 0;
                        strncpy(outside_crypt, outside, sizeof(outside_crypt) - 1);
                        break;
                case Digest_Md5:
                {
                        char id[STRLEN];
                        char salt[STRLEN];
                        char *temp;
                        /* A password looks like this,
                         *   $id$salt$digest
                         * the '$' around the id are still part of the id.
                         */
                        id[sizeof(id) - 1] = 0;
                        strncpy(id, c->passwd, sizeof(id) - 1);
                        if (! (temp = strchr(id + 1, '$'))) {
                                Log_error("Password not in MD5 format.\n");
                                return false;
                        }
                        temp += 1;
                        *temp = '\0';
                        salt[sizeof(salt) - 1] = 0;
                        strncpy(salt, c->passwd + strlen(id), sizeof(salt) - 1);
                        if (! (temp = strchr(salt, '$'))) {
                                Log_error("Password not in MD5 format.\n");
                                return false;
                        }
                        *temp = '\0';
                        if (md5_crypt(outside, id, salt, outside_crypt, sizeof(outside_crypt)) == NULL) {
                                Log_error("Cannot generate MD5 digest error.\n");
                                return false;
                        }
                        break;
                }
                case Digest_Crypt:
                {
                        char salt[3];
                        char *temp;
                        snprintf(salt, 3, "%c%c", c->passwd[0], c->passwd[1]);
                        temp = crypt(outside, salt);
                        outside_crypt[sizeof(outside_crypt) - 1] = 0;
                        strncpy(outside_crypt, temp, sizeof(outside_crypt) - 1);
                        break;
                }
#ifdef HAVE_LIBPAM
                case Digest_Pam:
                        return PAMcheckPasswd(uname, outside);
                        break;
#endif
                default:
                        Log_error("Unknown password digestion method.\n");
                        return false;
        }
        if (Str_compareConstantTime(outside_crypt, c->passwd) == 0)
                return true;
        return false;
}


void Util_swapFilesystemFlags(FilesystemFlags_T flags) {
        char *temp = flags->previous;
        flags->previous = flags->current;
        flags->current = temp;
        *(flags->current) = 0;
}


static void _resetFilesystemFlags(FilesystemFlags_T flags) {
        flags->previous = flags->value[0];
        flags->current = flags->value[1];
        *(flags->current) = 0;
        *(flags->previous) = 0;
}

static void _resetIOStatistics(IOStatistics_T S) {
        Statistics_reset(&(S->operations));
        Statistics_reset(&(S->bytes));
}


void Util_resetInfo(Service_T s) {
        switch (s->type) {
                case Service_Filesystem:
                        s->inf.filesystem->f_bsize = 0LL;
                        s->inf.filesystem->f_blocks = 0LL;
                        s->inf.filesystem->f_blocksfree = 0LL;
                        s->inf.filesystem->f_blocksfreetotal = 0LL;
                        s->inf.filesystem->f_blocksused = 0LL;
                        s->inf.filesystem->f_files = 0LL;
                        s->inf.filesystem->f_filesfree = 0LL;
                        s->inf.filesystem->f_filesused = 0LL;
                        s->inf.filesystem->inode_percent = 0.;
                        s->inf.filesystem->space_percent = 0.;
                        s->inf.filesystem->mode = -1;
                        s->inf.filesystem->uid = -1;
                        s->inf.filesystem->gid = -1;
                        _resetFilesystemFlags(&(s->inf.filesystem->flags));
                        _resetIOStatistics(&(s->inf.filesystem->read));
                        _resetIOStatistics(&(s->inf.filesystem->write));
                        Statistics_reset(&(s->inf.filesystem->time.read));
                        Statistics_reset(&(s->inf.filesystem->time.write));
                        Statistics_reset(&(s->inf.filesystem->time.wait));
                        Statistics_reset(&(s->inf.filesystem->time.run));
                        break;
                case Service_File:
                        s->inf.file->size  = -1;
                        s->inf.file->readpos = 0;
                        s->inf.file->inode = 0;
                        s->inf.file->inode_prev = 0;
                        s->inf.file->mode = -1;
                        s->inf.file->uid = -1;
                        s->inf.file->gid = -1;
                        s->inf.file->timestamp.access = 0;
                        s->inf.file->timestamp.change = 0;
                        s->inf.file->timestamp.modify = 0;
                        *s->inf.file->cs_sum = 0;
                        break;
                case Service_Directory:
                        s->inf.directory->mode = -1;
                        s->inf.directory->uid = -1;
                        s->inf.directory->gid = -1;
                        s->inf.directory->timestamp.access = 0;
                        s->inf.directory->timestamp.change = 0;
                        s->inf.directory->timestamp.modify = 0;
                        break;
                case Service_Fifo:
                        s->inf.fifo->mode = -1;
                        s->inf.fifo->uid = -1;
                        s->inf.fifo->gid = -1;
                        s->inf.fifo->timestamp.access = 0;
                        s->inf.fifo->timestamp.change = 0;
                        s->inf.fifo->timestamp.modify = 0;
                        break;
                case Service_Process:
                        s->inf.process->_pid = -1;
                        s->inf.process->_ppid = -1;
                        s->inf.process->pid = -1;
                        s->inf.process->ppid = -1;
                        s->inf.process->uid = -1;
                        s->inf.process->euid = -1;
                        s->inf.process->gid = -1;
                        s->inf.process->zombie = false;
                        s->inf.process->threads = -1;
                        s->inf.process->children = -1;
                        s->inf.process->mem = 0ULL;
                        s->inf.process->total_mem = 0ULL;
                        s->inf.process->mem_percent = -1.;
                        s->inf.process->total_mem_percent = -1.;
                        s->inf.process->cpu_percent = -1.;
                        s->inf.process->total_cpu_percent = -1.;
                        s->inf.process->uptime = -1;
                        s->inf.process->filedescriptors.open = -1LL;
                        s->inf.process->filedescriptors.openTotal = -1LL;
                        *(s->inf.process->secattr) = 0;
                        _resetIOStatistics(&(s->inf.process->read));
                        _resetIOStatistics(&(s->inf.process->write));
                        break;
                case Service_Net:
                        if (s->inf.net->stats)
                                Link_reset(s->inf.net->stats);
                        break;
                default:
                        break;
        }
}


bool Util_hasServiceStatus(Service_T s) {
        return((s->monitor & Monitor_Yes) && ! (s->error & Event_NonExist) && ! (s->error & Event_Data));
}


char *Util_getHTTPHostHeader(Socket_T s, char *hostBuf, int len) {
        int port = Socket_getRemotePort(s);
        const char *host = Socket_getRemoteHost(s);
        bool ipv6 = Str_sub(host, ":") ? true : false;
        if (port == 80 || port == 443)
                snprintf(hostBuf, len, "%s%s%s", ipv6 ? "[" : "", host, ipv6 ? "]" : "");
        else
                snprintf(hostBuf, len, "%s%s%s:%d", ipv6 ? "[" : "", host, ipv6 ? "]" : "", port);
        return hostBuf;
}


bool Util_evalQExpression(Operator_Type operator, long long left, long long right) {
        switch (operator) {
                case Operator_Greater:
                        if (left > right)
                                return true;
                        break;
                case Operator_GreaterOrEqual:
                        if (left >= right)
                                return true;
                        break;
                case Operator_Less:
                        if (left < right)
                                return true;
                        break;
                case Operator_LessOrEqual:
                        if (left <= right)
                                return true;
                        break;
                case Operator_Equal:
                        if (left == right)
                                return true;
                        break;
                case Operator_NotEqual:
                case Operator_Changed:
                        if (left != right)
                                return true;
                        break;
                default:
                        Log_error("Unknown comparison operator\n");
                        return false;
        }
        return false;
}


bool Util_evalDoubleQExpression(Operator_Type operator, double left, double right) {
        switch (operator) {
                case Operator_Greater:
                        if (left > right)
                                return true;
                        break;
                case Operator_GreaterOrEqual:
                        if (left >= right)
                                return true;
                        break;
                case Operator_Less:
                        if (left < right)
                                return true;
                        break;
                case Operator_LessOrEqual:
                        if (left <= right)
                                return true;
                        break;
                case Operator_Equal:
                        if (left == right)
                                return true;
                        break;
                case Operator_NotEqual:
                case Operator_Changed:
                        if (left != right)
                                return true;
                        break;
                default:
                        Log_error("Unknown comparison operator\n");
                        return false;
        }
        return false;
}


void Util_monitorSet(Service_T s) {
        ASSERT(s);
        if (s->monitor == Monitor_Not) {
                s->monitor = Monitor_Init;
                DEBUG("'%s' monitoring enabled\n", s->name);
                State_dirty();
        }
}


void Util_monitorUnset(Service_T s) {
        ASSERT(s);
        if (s->monitor != Monitor_Not) {
                s->monitor = Monitor_Not;
                DEBUG("'%s' monitoring disabled\n", s->name);
        }
        s->nstart = 0;
        s->ncycle = 0;
        if (s->every.type == Every_SkipCycles)
                s->every.spec.cycle.counter = 0;
        s->error = Event_Null;
        if (s->eventlist)
                gc_event(&s->eventlist);
        Util_resetInfo(s);
        State_dirty();
}


int Util_getAction(const char *action) {
        int i = 1; /* the Action_Ignored has index 0 => we will start on next item */

        ASSERT(action);

        while (strlen(actionnames[i])) {
                if (IS(action, actionnames[i]))
                        return i;
                i++;
        }
        /* the action was not found */
        return Action_Ignored;
}


StringBuffer_T Util_printAction(Action_T A, StringBuffer_T buf) {
        StringBuffer_append(buf, "%s", actionnames[A->id]);
        if (A->id == Action_Exec) {
                command_t C = A->exec;
                for (int i = 0; C->arg[i]; i++)
                        StringBuffer_append(buf, "%s%s", i ? " " : " '", C->arg[i]);
                StringBuffer_append(buf, "'");
                if (C->has_uid)
                        StringBuffer_append(buf, " as uid %d", C->uid);
                if (C->has_gid)
                        StringBuffer_append(buf, " as gid %d", C->gid);
                if (C->timeout)
                        StringBuffer_append(buf, " timeout %d cycle(s)", C->timeout);
                if (A->repeat)
                        StringBuffer_append(buf, " repeat every %d cycle(s)", A->repeat);
        }
        return buf;
}


StringBuffer_T Util_printEventratio(Action_T action, StringBuffer_T buf) {
        if (action->cycles > 1) {
                if (action->count == action->cycles)
                        StringBuffer_append(buf, "for %d cycles ", action->cycles);
                else
                        StringBuffer_append(buf, "for %d times within %d cycles ", action->count, action->cycles);
        }
        return buf;
}


StringBuffer_T Util_printRule(bool inverse, StringBuffer_T buf, EventAction_T action, const char *rule, ...) {
        ASSERT(buf);
        ASSERT(action);
        ASSERT(rule);
        // Variable part
        va_list ap;
        va_start(ap, rule);
        StringBuffer_vappend(buf, rule, ap);
        va_end(ap);
        // Constant part (failure action)
        StringBuffer_append(buf, " ");
        Util_printEventratio(action->failed, buf);
        StringBuffer_append(buf, "then ");
        Util_printAction(action->failed, buf);
        // Print the success part only if it's non default action (alert is implicit => skipped for simpler output)
        if (action->succeeded->id != Action_Ignored && action->succeeded->id != Action_Alert) {
                StringBuffer_append(buf, " else if ");
                StringBuffer_append(buf, inverse ? "failed " : "succeeded ");
                Util_printEventratio(action->succeeded, buf);
                StringBuffer_append(buf, "then ");
                Util_printAction(action->succeeded, buf);
        }
        return buf;
}


const char *Util_portIpDescription(Port_T p) {
        switch (p->family) {
                case Socket_Ip:
                        return "IP";
                case Socket_Ip4:
                        return "IPv4";
                case Socket_Ip6:
                        return "IPv6";
                default:
                        return "UNKNOWN";
        }
}


const char *Util_portTypeDescription(Port_T p) {
        switch (p->type) {
                case Socket_Tcp:
                        return "TCP";
                case Socket_Udp:
                        return "UDP";
                default:
                        return "UNKNOWN";
        }
}


const char *Util_portRequestDescription(Port_T p) {
        const char *request = "";
        if (p->protocol->check == check_http && p->parameters.http.request)
                request = p->parameters.http.request;
        else if (p->protocol->check == check_websocket && p->parameters.websocket.request)
                request = p->parameters.websocket.request;
        return request;
}


char *Util_portDescription(Port_T p, char *buf, int bufsize) {
        if (p->family == Socket_Ip || p->family == Socket_Ip4 || p->family == Socket_Ip6) {
                snprintf(buf, bufsize, "[%s]:%d%s [%s/%s%s]", p->hostname, p->target.net.port, Util_portRequestDescription(p), Util_portTypeDescription(p), Util_portIpDescription(p), p->target.net.ssl.options.flags ? " TLS" : "");
        } else if (p->family == Socket_Unix) {
                snprintf(buf, bufsize, "%s", p->target.unix.pathname);
        } else {
                *buf = 0;
        }
        return buf;
}


char *Util_commandDescription(command_t command, char s[STRLEN]) {
        ASSERT(s);
        ASSERT(command);
        int len = 0;
        for (int i = 0; command->arg[i] && len < STRLEN - 1; i++) {
                len += snprintf(s + len, STRLEN - len, "%s%s", i ? " " : "", command->arg[i]);
        }
        if (len >= STRLEN - 1)
                snprintf(s + STRLEN - 3 - 1, 4, "...");
        return s;
}


const char *Util_timestr(int time) {
        int i = 0;
        struct mytimetable {
                int id;
                const char *description;
        } tt[]= {
                {Time_Second, "second"},
                {Time_Minute, "minute"},
                {Time_Hour,   "hour"},
                {Time_Day,    "day"},
                {Time_Month,  "month"},
                {0}
        };
        do {
                if (time == tt[i].id)
                        return tt[i].description;
        } while (tt[++i].description);
        return NULL;
}

