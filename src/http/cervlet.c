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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
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

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

// libmonit
#include "system/Time.h"
#include "util/Fmt.h"
#include "util/List.h"

#include "monit.h"
#include "cervlet.h"
#include "engine.h"
#include "processor.h"
#include "base64.h"
#include "event.h"
#include "alert.h"
#include "ProcessTree.h"
#include "device.h"
#include "protocol.h"
#include "TextColor.h"
#include "TextBox.h"


#define ACTION(c) ! strncasecmp(req->url, c, sizeof(c))


/* URL Commands supported */
#define HOME        "/"
#define TEST        "/_monit"
#define ABOUT       "/_about"
#define PING        "/_ping"
#define GETID       "/_getid"
#define STATUS      "/_status"
#define STATUS2     "/_status2"
#define SUMMARY     "/_summary"
#define REPORT      "/_report"
#define RUNTIME     "/_runtime"
#define VIEWLOG     "/_viewlog"
#define DOACTION    "/_doaction"
#define FAVICON     "/favicon.ico"

// Limit for the viewlog response
#define VIEWLOG_LIMIT 1048576


typedef enum {
        TXT = 0,
        HTML
} __attribute__((__packed__)) Output_Type;


typedef struct ServiceMap_T {
        int found;
        union {
                struct {
                        const char *name;
                        const char *token;
                        Action_Type id;
                } action;
                struct {
                        HttpResponse res;
                } status;
                struct {
                        TextBox_T box;
                } summary;
        } data;
} *ServiceMap_T;


typedef struct ReportStatics_T {
        float up;
        float down;
        float init;
        float unmonitored;
        float total;
} *ReportStatics_T;


/* Private prototypes */
static bool is_readonly(HttpRequest);
static void printFavicon(HttpResponse);
static void doGet(HttpRequest, HttpResponse);
static void doPost(HttpRequest, HttpResponse);
static void do_head(HttpResponse res, const char *path, const char *name, int refresh);
static void do_foot(HttpResponse res);
static void do_home(HttpResponse);
static void do_home_system(HttpResponse);
static void do_home_filesystem(HttpResponse);
static void do_home_directory(HttpResponse);
static void do_home_file(HttpResponse);
static void do_home_fifo(HttpResponse);
static void do_home_net(HttpResponse);
static void do_home_process(HttpResponse);
static void do_home_program(HttpResponse);
static void do_home_host(HttpResponse);
static void do_about(HttpResponse);
static void do_ping(HttpResponse);
static void do_getid(HttpResponse);
static void do_runtime(HttpRequest, HttpResponse);
static void do_viewlog(HttpRequest, HttpResponse);
static void handle_service(HttpRequest, HttpResponse);
static void handle_service_action(HttpRequest, HttpResponse);
static void handle_doaction(HttpRequest, HttpResponse);
static void handle_runtime(HttpRequest, HttpResponse);
static void handle_runtime_action(HttpRequest, HttpResponse);
static void is_monit_running(HttpResponse);
static void do_service(HttpRequest, HttpResponse, Service_T);
static void print_alerts(HttpResponse, Mail_T);
static void print_buttons(HttpRequest, HttpResponse, Service_T);
static void print_service_rules_timeout(HttpResponse, Service_T);
static void print_service_rules_nonexistence(HttpResponse, Service_T);
static void print_service_rules_existence(HttpResponse, Service_T);
static void print_service_rules_port(HttpResponse, Service_T);
static void print_service_rules_socket(HttpResponse, Service_T);
static void print_service_rules_icmp(HttpResponse, Service_T);
static void print_service_rules_perm(HttpResponse, Service_T);
static void print_service_rules_uid(HttpResponse, Service_T);
static void print_service_rules_euid(HttpResponse, Service_T);
static void print_service_rules_gid(HttpResponse, Service_T);
static void print_service_rules_timestamp(HttpResponse, Service_T);
static void print_service_rules_fsflags(HttpResponse, Service_T);
static void print_service_rules_filesystem(HttpResponse, Service_T);
static void print_service_rules_size(HttpResponse, Service_T);
static void print_service_rules_nlink(HttpResponse, Service_T);
static void print_service_rules_linkstatus(HttpResponse, Service_T);
static void print_service_rules_linkspeed(HttpResponse, Service_T);
static void print_service_rules_linksaturation(HttpResponse, Service_T);
static void print_service_rules_uploadbytes(HttpResponse, Service_T);
static void print_service_rules_uploadpackets(HttpResponse, Service_T);
static void print_service_rules_downloadbytes(HttpResponse, Service_T);
static void print_service_rules_downloadpackets(HttpResponse, Service_T);
static void print_service_rules_uptime(HttpResponse, Service_T);
static void print_service_rules_content(HttpResponse, Service_T);
static void print_service_rules_checksum(HttpResponse, Service_T);
static void print_service_rules_pid(HttpResponse, Service_T);
static void print_service_rules_ppid(HttpResponse, Service_T);
static void print_service_rules_program(HttpResponse, Service_T);
static void print_service_rules_resource(HttpResponse, Service_T);
static void print_service_rules_secattr(HttpResponse, Service_T);
static void print_service_rules_filedescriptors(HttpResponse, Service_T);
static void print_status(HttpRequest, HttpResponse, int);
static void print_summary(HttpRequest, HttpResponse);
static void _printReport(HttpRequest req, HttpResponse res);
static void status_service_txt(Service_T, HttpResponse);
static char *get_monitoring_status(Output_Type, Service_T s, char *, int);
static char *get_service_status(Output_Type, Service_T, char *, int);


/**
 *  Implementation of doGet and doPost routines used by the cervlet
 *  processor module. This particilary cervlet will provide
 *  information about the monit daemon and programs monitored by
 *  monit.
 *
 *  @file
 */


/* ------------------------------------------------------------------ Public */


/**
 * Callback hook to the Processor module for registering this modules
 * doGet and doPost methods.
 */
void init_service(void) {
        add_Impl(doGet, doPost);
}


/* ----------------------------------------------------------------- Private */


static void _printServiceSummary(TextBox_T t, Service_T s) {
        TextBox_setColumn(t, 1, "%s", s->name);
        TextBox_setColumn(t, 2, "%s", get_service_status(TXT, s, (char[STRLEN]){}, STRLEN));
        TextBox_setColumn(t, 3, "%s", Servicetype_Names[s->type]);
        TextBox_printRow(t);
}


static void _serviceMapByName(const char *pattern, void (*callback)(Service_T s, ServiceMap_T ap), ServiceMap_T ap) {
        // Check the service name using the following sequence:
        // 1) if the pattern is NULL, any service will match
        // 2) backard compatibility: before monit 5.28.0 there was no support for regular expresion => check verbatim match before trying regex (the service may contain special characters)
        // 3) regex match
        if (pattern) {
                int rv;
                regex_t r;
                char patternEscaped[STRLEN];
                const char *patternCursor;

                // If the pattern doesn't contain "^" or "$" already, wrap it as "^<pattern>$" to prevent match with services that contain the given substring only
                if (! Str_has("^$", pattern)) {
                        snprintf(patternEscaped, sizeof(patternEscaped), "^%s$", pattern);
                        patternCursor = patternEscaped;
                } else {
                        patternCursor = pattern;
                }

                // The pattern is set, try to compile it as regex
                if ((rv = regcomp(&r, patternCursor, REG_NOSUB | REG_EXTENDED | REG_ICASE))) {
                        // Pattern compilation failed, fallback to verbatim match (before monit 5.28.0 there was no support for regular expresion)
                        char error[STRLEN];

                        regerror(rv, &r, error, STRLEN);
                        regfree(&r);
                        DEBUG("Regex %s parsing error: %s\n", patternCursor, error);

                        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                                if (IS(pattern, s->name)) { // Use the unescaped/original pattern
                                        callback(s, ap);
                                        ap->found++;
                                }
                        }
                } else {
                        // Regular expression match
                        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                                if (! regexec(&r, s->name, 0, NULL, 0)) {
                                        callback(s, ap);
                                        ap->found++;
                                }
                        }
                        regfree(&r);
                }


        } else {
                // Pattern is not set, any service will match
                for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                        callback(s, ap);
                        ap->found++;
                }
        }
}


static void _serviceMapByType(Service_Type type, void (*callback)(Service_T s, ServiceMap_T ap), ServiceMap_T ap) {
        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                if (s->type == type) {
                        callback(s, ap);
                        ap->found++;
                }
        }
}


static void _serviceMapSummary(Service_T s, ServiceMap_T ap) {
        _printServiceSummary(ap->data.summary.box, s);
}


static void _serviceMapStatus(Service_T s, ServiceMap_T ap) {
        status_service_txt(s, ap->data.status.res);
}


static void _serviceMapAction(Service_T s, ServiceMap_T ap) {
        s->doaction = ap->data.action.id;
        Log_info("'%s' %s on user request\n", s->name, ap->data.action.name);
}


static char *_getUptime(time_t delta, char s[256]) {
        static int min = 60;
        static int hour = 3600;
        static int day = 86400;
        long rest_d;
        long rest_h;
        long rest_m;
        char *p = s;

        if (delta < 0) {
                *s = 0;
        } else {
                if ((rest_d = delta / day) > 0) {
                        p += snprintf(p, 256 - (p - s), "%ldd ", rest_d);
                        delta -= rest_d * day;
                }
                if ((rest_h = delta / hour) > 0 || (rest_d > 0)) {
                        p += snprintf(p, 256 - (p - s), "%ldh ", rest_h);
                        delta -= rest_h * hour;
                }
                rest_m = delta / min;
                snprintf(p, 256 - (p - s), "%ldm", rest_m);
        }
        return s;
}


__attribute__((format (printf, 7, 8))) static void _formatStatus(const char *name, Event_Type errorType, Output_Type type, HttpResponse res, Service_T s, bool validValue, const char *value, ...) {
        if (type == HTML) {
                StringBuffer_append(res->outputbuffer, "<tr><td>%c%s</td>", toupper(name[0]), name + 1);
        } else {
                StringBuffer_append(res->outputbuffer, "  %-28s ", name);
        }
        if (! validValue) {
                StringBuffer_append(res->outputbuffer, type == HTML ? "<td class='gray-text'>-</td>" : COLOR_DARKGRAY "-" COLOR_RESET);
        } else {
                va_list ap;
                va_start(ap, value);
                char *_value = Str_vcat(value, ap);
                va_end(ap);

                if (errorType != Event_Null && s->error & errorType)
                        StringBuffer_append(res->outputbuffer, type == HTML ? "<td class='red-text'>" : COLOR_LIGHTRED);
                else
                        StringBuffer_append(res->outputbuffer, type == HTML ? "<td>" : COLOR_DEFAULT);

                if (type == HTML) {
                        // If the output contains multiple line, wrap use <pre>, otherwise keep as is
                        bool multiline = strrchr(_value, '\n') ? true : false;
                        if (multiline)
                                StringBuffer_append(res->outputbuffer, "<pre>");
                        escapeHTML(res->outputbuffer, _value);
                        StringBuffer_append(res->outputbuffer, "%s</td>", multiline ? "</pre>" : "");
                } else {
                        int column = 0;
                        for (int i = 0; _value[i]; i++) {
                                if (_value[i] == '\r') {
                                        // Discard CR
                                        continue;
                                } else if (_value[i] == '\n') {
                                        // Indent 2nd+ line
                                        if (_value[i + 1])
                                        StringBuffer_append(res->outputbuffer, "\n                               ");
                                        column = 0;
                                        continue;
                                } else if (column <= 200) {
                                        StringBuffer_append(res->outputbuffer, "%c", _value[i]);
                                        column++;
                                }
                        }
                        StringBuffer_append(res->outputbuffer, COLOR_RESET);
                }
                FREE(_value);
        }
        StringBuffer_append(res->outputbuffer, type == HTML ? "</tr>" : "\n");
}


static void _printIOStatistics(Output_Type type, HttpResponse res, Service_T s, IOStatistics_T io, const char *name) {
        char header[STRLEN] = {};
        if (Statistics_initialized(&(io->bytes))) {
                snprintf(header, sizeof(header), "%s bytes", name);
                double deltaBytesPerSec = Statistics_deltaNormalize(&(io->bytes));
                _formatStatus(header, Event_Resource, type, res, s, true, "%s/s [%s total]", Fmt_bytes2str(deltaBytesPerSec, (char[10]){}), Fmt_bytes2str(Statistics_raw(&(io->bytes)), (char[10]){}));
        }
        if (Statistics_initialized(&(io->bytesPhysical))) {
                snprintf(header, sizeof(header), "disk %s bytes", name);
                double deltaBytesPerSec = Statistics_deltaNormalize(&(io->bytesPhysical));
                _formatStatus(header, Event_Resource, type, res, s, true, "%s/s [%s total]", Fmt_bytes2str(deltaBytesPerSec, (char[10]){}), Fmt_bytes2str(Statistics_raw(&(io->bytesPhysical)), (char[10]){}));
        }
        if (Statistics_initialized(&(io->operations))) {
                snprintf(header, sizeof(header), "disk %s operations", name);
                double deltaOpsPerSec = Statistics_deltaNormalize(&(io->operations));
                _formatStatus(header, Event_Resource, type, res, s, true, "%.1f %ss/s [%llu %ss total]", deltaOpsPerSec, name, Statistics_raw(&(io->operations)), name);
        }
}


static void _printStatus(Output_Type type, HttpResponse res, Service_T s) {
        if (Util_hasServiceStatus(s)) {
                switch (s->type) {
                        case Service_System:
                                {
                                        _formatStatus("load average", Event_Resource, type, res, s, true, "[%.2f] [%.2f] [%.2f]", System_Info.loadavg[0], System_Info.loadavg[1], System_Info.loadavg[2]);
                                        StringBuffer_T sb = StringBuffer_create(256);
                                        if (System_Info.statisticsAvailable & Statistics_CpuUser)
                                                StringBuffer_append(sb, "%.1f%%usr ", System_Info.cpu.usage.user > 0. ? System_Info.cpu.usage.user : 0.);
                                        if (System_Info.statisticsAvailable & Statistics_CpuSystem)
                                                StringBuffer_append(sb, "%.1f%%sys ", System_Info.cpu.usage.system > 0. ? System_Info.cpu.usage.system : 0.);
                                        if (System_Info.statisticsAvailable & Statistics_CpuNice)
                                                StringBuffer_append(sb, "%.1f%%nice ", System_Info.cpu.usage.nice > 0. ? System_Info.cpu.usage.nice : 0.);
                                        if (System_Info.statisticsAvailable & Statistics_CpuIOWait)
                                                StringBuffer_append(sb, "%.1f%%iowait ", System_Info.cpu.usage.iowait > 0. ? System_Info.cpu.usage.iowait : 0.);
                                        if (System_Info.statisticsAvailable & Statistics_CpuHardIRQ)
                                                StringBuffer_append(sb, "%.1f%%hardirq ", System_Info.cpu.usage.hardirq > 0. ? System_Info.cpu.usage.hardirq : 0.);
                                        if (System_Info.statisticsAvailable & Statistics_CpuSoftIRQ)
                                                StringBuffer_append(sb, "%.1f%%softirq ", System_Info.cpu.usage.softirq > 0. ? System_Info.cpu.usage.softirq : 0.);
                                        if (System_Info.statisticsAvailable & Statistics_CpuSteal)
                                                StringBuffer_append(sb, "%.1f%%steal ", System_Info.cpu.usage.steal > 0. ? System_Info.cpu.usage.steal : 0.);
                                        if (System_Info.statisticsAvailable & Statistics_CpuGuest)
                                                StringBuffer_append(sb, "%.1f%%guest ", System_Info.cpu.usage.guest > 0. ? System_Info.cpu.usage.guest : 0.);
                                        if (System_Info.statisticsAvailable & Statistics_CpuGuestNice)
                                                StringBuffer_append(sb, "%.1f%%guestnice ", System_Info.cpu.usage.guest_nice > 0. ? System_Info.cpu.usage.guest_nice : 0.);
                                        _formatStatus("cpu", Event_Resource, type, res, s, true, "%s", StringBuffer_toString(sb));
                                        StringBuffer_free(&sb);
                                        _formatStatus("memory usage", Event_Resource, type, res, s, true, "%s [%.1f%%]", Fmt_bytes2str(System_Info.memory.usage.bytes, (char[10]){}), System_Info.memory.usage.percent);
                                        _formatStatus("swap usage", Event_Resource, type, res, s, true, "%s [%.1f%%]", Fmt_bytes2str(System_Info.swap.usage.bytes, (char[10]){}), System_Info.swap.usage.percent);
                                        _formatStatus("uptime", Event_Uptime, type, res, s, System_Info.booted > 0, "%s", _getUptime(Time_now() - System_Info.booted, (char[256]){}));
                                        _formatStatus("boot time", Event_Null, type, res, s, true, "%s", Time_string(System_Info.booted, (char[32]){}));
                                        if (System_Info.statisticsAvailable & Statistics_FiledescriptorsPerSystem) {
                                                if (System_Info.filedescriptors.maximum > 0)
                                                        _formatStatus("filedescriptors", Event_Resource, type, res, s, true, "%lld [%.1f%% of %lld limit]", System_Info.filedescriptors.allocated, (float)100 * (float)System_Info.filedescriptors.allocated / (float)System_Info.filedescriptors.maximum, System_Info.filedescriptors.maximum);
                                                else
                                                        _formatStatus("filedescriptors", Event_Resource, type, res, s, true, "N/A");
                                        }
                                }
                                break;

                        case Service_File:
                                _formatStatus("permission", Event_Permission, type, res, s, s->inf.file->mode >= 0, "%o", s->inf.file->mode & 07777);
                                _formatStatus("uid", Event_Uid, type, res, s, s->inf.file->uid >= 0, "%d", s->inf.file->uid);
                                _formatStatus("gid", Event_Gid, type, res, s, s->inf.file->gid >= 0, "%d", s->inf.file->gid);
                                _formatStatus("size", Event_Size, type, res, s, s->inf.file->size >= 0, "%s", Fmt_bytes2str(s->inf.file->size, (char[10]){}));
                                _formatStatus("hardlink", Event_Resource, type, res, s, s->inf.file->nlink != -1LL, "%llu", (unsigned long long)s->inf.file->nlink);
                                _formatStatus("access timestamp", Event_Timestamp, type, res, s, s->inf.file->timestamp.access > 0, "%s", Time_string(s->inf.file->timestamp.access, (char[32]){}));
                                _formatStatus("change timestamp", Event_Timestamp, type, res, s, s->inf.file->timestamp.change > 0, "%s", Time_string(s->inf.file->timestamp.change, (char[32]){}));
                                _formatStatus("modify timestamp", Event_Timestamp, type, res, s, s->inf.file->timestamp.modify > 0, "%s", Time_string(s->inf.file->timestamp.modify, (char[32]){}));
                                if (s->matchlist)
                                        _formatStatus("content match", Event_Content, type, res, s, true, "%s", (s->error & Event_Content) ? "yes" : "no");
                                if (s->checksum)
                                        _formatStatus("checksum", Event_Checksum, type, res, s, *s->inf.file->cs_sum, "%s (%s)", s->inf.file->cs_sum, Checksum_Names[s->checksum->type]);
                                break;

                        case Service_Directory:
                                _formatStatus("permission", Event_Permission, type, res, s, s->inf.directory->mode >= 0, "%o", s->inf.directory->mode & 07777);
                                _formatStatus("uid", Event_Uid, type, res, s, s->inf.directory->uid >= 0, "%d", s->inf.directory->uid);
                                _formatStatus("gid", Event_Gid, type, res, s, s->inf.directory->gid >= 0, "%d", s->inf.directory->gid);
                                _formatStatus("hardlink", Event_Resource, type, res, s, s->inf.directory->nlink != -1LL, "%llu", (unsigned long long)s->inf.directory->nlink);
                                _formatStatus("access timestamp", Event_Timestamp, type, res, s, s->inf.directory->timestamp.access > 0, "%s", Time_string(s->inf.directory->timestamp.access, (char[32]){}));
                                _formatStatus("change timestamp", Event_Timestamp, type, res, s, s->inf.directory->timestamp.change > 0, "%s", Time_string(s->inf.directory->timestamp.change, (char[32]){}));
                                _formatStatus("modify timestamp", Event_Timestamp, type, res, s, s->inf.directory->timestamp.modify > 0, "%s", Time_string(s->inf.directory->timestamp.modify, (char[32]){}));
                                break;

                        case Service_Fifo:
                                _formatStatus("permission", Event_Permission, type, res, s, s->inf.fifo->mode >= 0, "%o", s->inf.fifo->mode & 07777);
                                _formatStatus("uid", Event_Uid, type, res, s, s->inf.fifo->uid >= 0, "%d", s->inf.fifo->uid);
                                _formatStatus("gid", Event_Gid, type, res, s, s->inf.fifo->gid >= 0, "%d", s->inf.fifo->gid);
                                _formatStatus("hardlink", Event_Resource, type, res, s, s->inf.fifo->nlink != -1LL, "%llu", (unsigned long long)s->inf.fifo->nlink);
                                _formatStatus("access timestamp", Event_Timestamp, type, res, s, s->inf.fifo->timestamp.access > 0, "%s", Time_string(s->inf.fifo->timestamp.access, (char[32]){}));
                                _formatStatus("change timestamp", Event_Timestamp, type, res, s, s->inf.fifo->timestamp.change > 0, "%s", Time_string(s->inf.fifo->timestamp.change, (char[32]){}));
                                _formatStatus("modify timestamp", Event_Timestamp, type, res, s, s->inf.fifo->timestamp.modify > 0, "%s", Time_string(s->inf.fifo->timestamp.modify, (char[32]){}));
                                break;

                        case Service_Net:
                                {
                                        long long speed = Link_getSpeed(s->inf.net->stats);
                                        long long ibytes = Link_getBytesInPerSecond(s->inf.net->stats);
                                        long long obytes = Link_getBytesOutPerSecond(s->inf.net->stats);
                                        _formatStatus("link", Event_Link, type, res, s, Link_getState(s->inf.net->stats) == 1, "%lld errors", Link_getErrorsInPerSecond(s->inf.net->stats) + Link_getErrorsOutPerSecond(s->inf.net->stats));
                                        if (speed > 0) {
                                                _formatStatus("capacity", Event_Speed, type, res, s, Link_getState(s->inf.net->stats) == 1, "%.0lf Mb/s %s-duplex", (double)speed / 1000000., Link_getDuplex(s->inf.net->stats) == 1 ? "full" : "half");
                                                _formatStatus("download bytes", Event_ByteIn, type, res, s, Link_getState(s->inf.net->stats) == 1, "%s/s (%.1f%% link saturation)", Fmt_bytes2str(ibytes, (char[10]){}), 100. * ibytes * 8 / (double)speed);
                                                _formatStatus("upload bytes", Event_ByteOut, type, res, s, Link_getState(s->inf.net->stats) == 1, "%s/s (%.1f%% link saturation)", Fmt_bytes2str(obytes, (char[10]){}), 100. * obytes * 8 / (double)speed);
                                        } else {
                                                _formatStatus("download bytes", Event_ByteIn, type, res, s, Link_getState(s->inf.net->stats) == 1, "%s/s", Fmt_bytes2str(ibytes, (char[10]){}));
                                                _formatStatus("upload bytes", Event_ByteOut, type, res, s, Link_getState(s->inf.net->stats) == 1, "%s/s", Fmt_bytes2str(obytes, (char[10]){}));
                                        }
                                        _formatStatus("download packets", Event_PacketIn, type, res, s, Link_getState(s->inf.net->stats) == 1, "%lld per second", Link_getPacketsInPerSecond(s->inf.net->stats));
                                        _formatStatus("upload packets", Event_PacketOut, type, res, s, Link_getState(s->inf.net->stats) == 1, "%lld per second", Link_getPacketsOutPerSecond(s->inf.net->stats));
                                }
                                break;

                        case Service_Filesystem:
                                _formatStatus("filesystem type", Event_Null, type, res, s, *(s->inf.filesystem->object.type), "%s", s->inf.filesystem->object.type);
                                _formatStatus("filesystem flags", Event_FsFlag, type, res, s, *(s->inf.filesystem->flags.current), "%s", s->inf.filesystem->flags.current);
                                _formatStatus("permission", Event_Permission, type, res, s, s->inf.filesystem->mode >= 0, "%o", s->inf.filesystem->mode & 07777);
                                _formatStatus("uid", Event_Uid, type, res, s, s->inf.filesystem->uid >= 0, "%d", s->inf.filesystem->uid);
                                _formatStatus("gid", Event_Gid, type, res, s, s->inf.filesystem->gid >= 0, "%d", s->inf.filesystem->gid);
                                _formatStatus("block size", Event_Null, type, res, s, true, "%s", Fmt_bytes2str(s->inf.filesystem->f_bsize, (char[10]){}));
                                _formatStatus("space total", Event_Null, type, res, s, true, "%s (of which %.1f%% is reserved for root user)",
                                        s->inf.filesystem->f_bsize > 0 ? Fmt_bytes2str(s->inf.filesystem->f_blocks * s->inf.filesystem->f_bsize, (char[10]){}) : "0 MB",
                                        s->inf.filesystem->f_blocks > 0 ? ((float)100 * (float)(s->inf.filesystem->f_blocksfreetotal - s->inf.filesystem->f_blocksfree) / (float)s->inf.filesystem->f_blocks) : 0);
                                _formatStatus("space free for non superuser", Event_Null, type, res, s, true, "%s [%.1f%%]",
                                        s->inf.filesystem->f_bsize > 0 ? Fmt_bytes2str(s->inf.filesystem->f_blocksfree * s->inf.filesystem->f_bsize, (char[10]){}) : "0 MB",
                                        s->inf.filesystem->f_blocks > 0 ? ((float)100 * (float)s->inf.filesystem->f_blocksfree / (float)s->inf.filesystem->f_blocks) : 0);
                                _formatStatus("space free total", Event_Resource, type, res, s, true, "%s [%.1f%%]",
                                        s->inf.filesystem->f_bsize > 0 ? Fmt_bytes2str(s->inf.filesystem->f_blocksfreetotal * s->inf.filesystem->f_bsize, (char[10]){}) : "0 MB",
                                        s->inf.filesystem->f_blocks > 0 ? ((float)100 * (float)s->inf.filesystem->f_blocksfreetotal / (float)s->inf.filesystem->f_blocks) : 0);
                                if (s->inf.filesystem->f_files > 0) {
                                        _formatStatus("inodes total", Event_Null, type, res, s, true, "%lld", s->inf.filesystem->f_files);
                                        if (s->inf.filesystem->f_filesfree > 0)
                                                _formatStatus("inodes free", Event_Resource, type, res, s, true, "%lld [%.1f%%]", s->inf.filesystem->f_filesfree, (float)100 * (float)s->inf.filesystem->f_filesfree / (float)s->inf.filesystem->f_files);
                                }
                                _printIOStatistics(type, res, s, &(s->inf.filesystem->read), "read");
                                _printIOStatistics(type, res, s, &(s->inf.filesystem->write), "write");
                                bool hasReadTime = Statistics_initialized(&(s->inf.filesystem->time.read));
                                bool hasWriteTime = Statistics_initialized(&(s->inf.filesystem->time.write));
                                bool hasWaitTime = Statistics_initialized(&(s->inf.filesystem->time.wait));
                                bool hasRunTime = Statistics_initialized(&(s->inf.filesystem->time.run));
                                double deltaOperations = Statistics_delta(&(s->inf.filesystem->read.operations)) + Statistics_delta(&(s->inf.filesystem->write.operations));
                                if (hasReadTime && hasWriteTime) {
                                        double readTime = deltaOperations > 0. ? Statistics_deltaNormalize(&(s->inf.filesystem->time.read)) / deltaOperations : 0.;
                                        double writeTime = deltaOperations > 0. ? Statistics_deltaNormalize(&(s->inf.filesystem->time.write)) / deltaOperations : 0.;
                                        _formatStatus("service time", Event_Null, type, res, s, true, "%.3f ms/operation (of which read %.3f ms, write %.3f ms)", readTime + writeTime, readTime, writeTime);
                                } else if (hasWaitTime && hasRunTime) {
                                        double waitTime = deltaOperations > 0. ? Statistics_deltaNormalize(&(s->inf.filesystem->time.wait)) / deltaOperations : 0.;
                                        double runTime = deltaOperations > 0. ? Statistics_deltaNormalize(&(s->inf.filesystem->time.run)) / deltaOperations : 0.;
                                        _formatStatus("service time", Event_Null, type, res, s, true, "%.3f ms/operation (of which queue %.3f ms, active %.3f ms)", waitTime + runTime, waitTime, runTime);
                                } else if (hasWaitTime) {
                                        double waitTime = deltaOperations > 0. ? Statistics_deltaNormalize(&(s->inf.filesystem->time.wait)) / deltaOperations : 0.;
                                        _formatStatus("service time", Event_Null, type, res, s, true, "%.3f ms/operation", waitTime);
                                } else if (hasRunTime) {
                                        double runTime = deltaOperations > 0. ? Statistics_deltaNormalize(&(s->inf.filesystem->time.run)) / deltaOperations : 0.;
                                        _formatStatus("service time", Event_Null, type, res, s, true, "%.3f ms/operation", runTime);
                                }
                                break;

                        case Service_Process:
                                _formatStatus("pid", Event_Pid, type, res, s, s->inf.process->pid >= 0, "%d", s->inf.process->pid);
                                _formatStatus("parent pid", Event_PPid, type, res, s, s->inf.process->ppid >= 0, "%d", s->inf.process->ppid);
                                _formatStatus("uid", Event_Uid, type, res, s, s->inf.process->uid >= 0, "%d", s->inf.process->uid);
                                _formatStatus("effective uid", Event_Uid, type, res, s, s->inf.process->euid >= 0, "%d", s->inf.process->euid);
                                _formatStatus("gid", Event_Gid, type, res, s, s->inf.process->gid >= 0, "%d", s->inf.process->gid);
                                _formatStatus("uptime", Event_Uptime, type, res, s, s->inf.process->uptime >= 0, "%s", _getUptime(s->inf.process->uptime, (char[256]){}));
                                if (Run.flags & Run_ProcessEngineEnabled) {
                                        _formatStatus("threads", Event_Resource, type, res, s, s->inf.process->threads >= 0, "%d", s->inf.process->threads);
                                        _formatStatus("children", Event_Resource, type, res, s, s->inf.process->children >= 0, "%d", s->inf.process->children);
                                        _formatStatus("cpu", Event_Resource, type, res, s, s->inf.process->cpu_percent >= 0, "%.1f%%", s->inf.process->cpu_percent);
                                        _formatStatus("cpu total", Event_Resource, type, res, s, s->inf.process->total_cpu_percent >= 0, "%.1f%%", s->inf.process->total_cpu_percent);
                                        _formatStatus("memory", Event_Resource, type, res, s, s->inf.process->mem_percent >= 0, "%.1f%% [%s]", s->inf.process->mem_percent, Fmt_bytes2str(s->inf.process->mem, (char[10]){}));
                                        _formatStatus("memory total", Event_Resource, type, res, s, s->inf.process->total_mem_percent >= 0, "%.1f%% [%s]", s->inf.process->total_mem_percent, Fmt_bytes2str(s->inf.process->total_mem, (char[10]){}));
#ifdef LINUX
                                        _formatStatus("security attribute", Event_Invalid, type, res, s, *(s->inf.process->secattr), "%s", s->inf.process->secattr);
                                        long long limit = s->inf.process->filedescriptors.limit.soft < s->inf.process->filedescriptors.limit.hard ? s->inf.process->filedescriptors.limit.soft : s->inf.process->filedescriptors.limit.hard;
                                        if (limit > 0)
                                                _formatStatus("filedescriptors", Event_Resource, type, res, s, s->inf.process->filedescriptors.open != -1LL, "%lld [%.1f%% of %lld limit]", s->inf.process->filedescriptors.open, (float)100 * (float)s->inf.process->filedescriptors.open / (float)limit, limit);
                                        else
                                                _formatStatus("filedescriptors", Event_Resource, type, res, s, s->inf.process->filedescriptors.open != -1LL, "N/A");
                                        _formatStatus("total filedescriptors", Event_Resource, type, res, s, s->inf.process->filedescriptors.openTotal != -1LL, "%lld", s->inf.process->filedescriptors.openTotal);
#endif
                                }
                                _printIOStatistics(type, res, s, &(s->inf.process->read), "read");
                                _printIOStatistics(type, res, s, &(s->inf.process->write), "write");
                                break;

                        case Service_Program:
                                if (s->program->started) {
                                        _formatStatus("last exit value", Event_Status, type, res, s, true, "%d", s->program->exitStatus);
                                        _formatStatus("last output", Event_Status, type, res, s, StringBuffer_length(s->program->lastOutput), "%s", StringBuffer_toString(s->program->lastOutput));
                                }
                                break;

                        default:
                                break;
                }
                for (Icmp_T i = s->icmplist; i; i = i->next) {
                        if (i->is_available == Connection_Failed)
                                _formatStatus("ping response time", i->check_invers ? Event_Null : Event_Icmp, type, res, s, true, "connection failed");
                        else
                                _formatStatus("ping response time", i->check_invers ? Event_Icmp : Event_Null, type, res, s, i->is_available != Connection_Init && i->responsetime.current >= 0., "%s", Fmt_time2str(i->responsetime.current, (char[11]){}));
                }
                for (Port_T p = s->portlist; p; p = p->next) {
                        if (p->is_available == Connection_Failed) {
                                Event_Type highlight = p->check_invers ? Event_Null : Event_Connection;
                                _formatStatus("port response time", highlight, type, res, s, true, "FAILED to [%s]:%d%s type %s/%s %sprotocol %s", p->hostname, p->target.net.port, Util_portRequestDescription(p), Util_portTypeDescription(p), Util_portIpDescription(p), p->target.net.ssl.options.flags ? "using TLS " : "", p->protocol->name);
                        } else {
                                char buf[STRLEN] = {};
                                if (p->target.net.ssl.options.flags)
                                        snprintf(buf, sizeof(buf), "using TLS (certificate valid for %d days) ", p->target.net.ssl.certificate.validDays);
                                Event_Type highlight = p->check_invers ? Event_Connection : Event_Null;
                                if (p->target.net.ssl.certificate.validDays < p->target.net.ssl.certificate.minimumDays)
                                        highlight |= Event_Timestamp;
                                _formatStatus("port response time", highlight, type, res, s, p->is_available != Connection_Init, "%s to %s:%d%s type %s/%s %sprotocol %s", Fmt_time2str(p->responsetime.current, (char[11]){}), p->hostname, p->target.net.port, Util_portRequestDescription(p), Util_portTypeDescription(p), Util_portIpDescription(p), buf, p->protocol->name);
                        }
                }
                for (Port_T p = s->socketlist; p; p = p->next) {
                        if (p->is_available == Connection_Failed) {
                                _formatStatus("unix socket response time", p->check_invers ? Event_Null : Event_Connection, type, res, s, true, "FAILED to %s type %s protocol %s", p->target.unix.pathname, Util_portTypeDescription(p), p->protocol->name);
                        } else {
                                _formatStatus("unix socket response time", p->check_invers ? Event_Connection : Event_Null, type, res, s, p->is_available != Connection_Init, "%s to %s type %s protocol %s", Fmt_time2str(p->responsetime.current, (char[11]){}), p->target.unix.pathname, Util_portTypeDescription(p), p->protocol->name);
                        }
                }
        }
        _formatStatus("data collected", Event_Null, type, res, s, true, "%s", Time_string(s->collected.tv_sec, (char[32]){}));
}


__attribute__((format (printf, 5, 6))) static void _displayTableRow(HttpResponse res, bool escape, const char *class, const char *key, const char *value, ...) {
        va_list ap;
        va_start(ap, value);
        char *_value = Str_vcat(value, ap);
        va_end(ap);

        if (STR_DEF(class))
                StringBuffer_append(res->outputbuffer, "<tr class='%s'><td>%s</td><td>", class, key);
        else
                StringBuffer_append(res->outputbuffer, "<tr><td>%s</td><td>", key);
        if (escape) {
                // If the data contains multiple lines, wrap use <pre>, otherwise keep as is
                bool multiline = strrchr(_value, '\n') ? true : false;
                if (multiline)
                        StringBuffer_append(res->outputbuffer, "<pre>");
                escapeHTML(res->outputbuffer, _value);
                if (multiline)
                        StringBuffer_append(res->outputbuffer, "</pre>");
        } else {
                StringBuffer_append(res->outputbuffer, "%s", _value);
        }
        StringBuffer_append(res->outputbuffer, "</td></tr>");
        FREE(_value);
}


static void _formatAction(HttpResponse res, const char *type, command_t cmd) {
        char key[STRLEN] = {};
        snprintf(key, sizeof(key), "%s program", type);
        StringBuffer_T sb = StringBuffer_create(256);
        StringBuffer_append(sb, "'%s'", Util_commandDescription(cmd, (char[STRLEN]){}));
        if (cmd->has_uid)
                StringBuffer_append(sb, " as uid %d", cmd->uid);
        if (cmd->has_gid)
                StringBuffer_append(sb, " as gid %d", cmd->gid);
        StringBuffer_append(sb, " timeout %s", Fmt_time2str(cmd->timeout, (char[11]){}));
        _displayTableRow(res, true, NULL, key, "%s", StringBuffer_toString(sb));
        StringBuffer_free(&sb);
}


static void _formatAddress(HttpResponse res, const char *type, Address_T addr) {
        char key[STRLEN] = {};
        snprintf(key, sizeof(key), "Default mail %s", type);
        if (addr->name)
                _displayTableRow(res, true, NULL, key, "%s <%s>", addr->name, addr->address);
        else
                _displayTableRow(res, true, NULL, key, "%s", addr->address);
}


/**
 * Called by the Processor (via the service method)
 * to handle a POST request.
 */
static void doPost(HttpRequest req, HttpResponse res) {
        set_content_type(res, "text/html");
        if (ACTION(RUNTIME))
                handle_runtime_action(req, res);
        else if (ACTION(VIEWLOG))
                do_viewlog(req, res);
        else if (ACTION(STATUS))
                print_status(req, res, 1);
        else if (ACTION(STATUS2))
                print_status(req, res, 2);
        else if (ACTION(SUMMARY))
                print_summary(req, res);
        else if (ACTION(REPORT))
                _printReport(req, res);
        else if (ACTION(DOACTION))
                handle_doaction(req, res);
        else
                handle_service_action(req, res);
        if (STR_DEF(req->url)) {
            // Send a proper status to handle errors
            if (res->status <= 300) {
                // #1009: Redirect back to the same url so a reload in the browser does not perform a POST again
                set_status(res, SC_MOVED_TEMPORARILY);
                set_header(res, "Location", "%s", req->url);
            }
        }
}


/**
 * Called by the Processor (via the service method)
 * to handle a GET request.
 */
static void doGet(HttpRequest req, HttpResponse res) {
        set_content_type(res, "text/html");
        if (ACTION(HOME)) {
                LOCK(Run.mutex)
                do_home(res);
                END_LOCK;
        } else if (ACTION(RUNTIME)) {
                handle_runtime(req, res);
        } else if (ACTION(TEST)) {
                is_monit_running(res);
        } else if (ACTION(ABOUT)) {
                do_about(res);
        } else if (ACTION(FAVICON)) {
                printFavicon(res);
        } else if (ACTION(PING)) {
                do_ping(res);
        } else if (ACTION(GETID)) {
                do_getid(res);
        } else if (ACTION(STATUS)) {
                print_status(req, res, 1);
        } else if (ACTION(STATUS2)) {
                print_status(req, res, 2);
        } else if (ACTION(SUMMARY)) {
                print_summary(req, res);
        } else if (ACTION(REPORT)) {
                _printReport(req, res);
        } else if (ACTION(VIEWLOG)) {
                do_viewlog(req, res);
        } else {
                handle_service(req, res);
        }
}


/* ----------------------------------------------------------------- Helpers */


static void is_monit_running(HttpResponse res) {
        set_status(res, exist_daemon() ? SC_OK : SC_GONE);
}


static void printFavicon(HttpResponse res) {
        static size_t l;
        Socket_T S = res->S;
        static unsigned char *favicon = NULL;

        if (! favicon) {
                favicon = CALLOC(sizeof(unsigned char), strlen(FAVICON_ICO));
                l = decode_base64(favicon, FAVICON_ICO);
        }
        if (l) {
                res->is_committed = true;
                Socket_print(S, "HTTP/1.0 200 OK\r\n");
                Socket_print(S, "Content-length: %lu\r\n", (unsigned long)l);
                Socket_print(S, "Content-Type: image/x-icon\r\n");
                Socket_print(S, "Connection: close\r\n\r\n");
                if (Socket_write(S, favicon, l) < 0) {
                        Log_error("Error sending favicon data -- %s\n", STRERROR);
                }
        }
}


static void do_head(HttpResponse res, const char *path, const char *name, int refresh) {
        StringBuffer_T system_htmlescaped = escapeHTML(StringBuffer_create(16), Run.system->name);
        StringBuffer_append(res->outputbuffer,
                            "<!DOCTYPE html>"\
                            "<html>"\
                            "<head>"\
                            "<title>Monit: %s</title> "\
                            "<style type=\"text/css\"> "\
                            " html, body {height: 100%%;margin: 0;} "\
                            " body {background-color: white;font: normal normal normal 16px/20px 'HelveticaNeue', Helvetica, Arial, sans-serif; color:#222;} "\
                            " h1 {padding:30px 0 10px 0; text-align:center;color:#222;font-size:28px;} "\
                            " h2 {padding:20px 0 10px 0; text-align:center;color:#555;font-size:22px;} "\
                            " a:hover {text-decoration: none;} "\
                            " a {text-decoration: underline;color:#222} "\
                            " table {border-collapse:collapse; border:0;} "\
                            " .stripe {background:#EDF5FF} "\
                            " .rule {background:#ddd} "\
                            " .red-text {color:#ff0000;} "\
                            " .green-text {color:#00ff00;} "\
                            " .gray-text {color:#999999;} "\
                            " .blue-text {color:#0000ff;} "\
                            " .yellow-text {color:#ffff00;} "\
                            " .orange-text {color:#ff8800;} "\
                            " .short {overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 350px;}"\
                            " .column {min-width: 80px;} "\
                            " .left {text-align:left} "\
                            " .right {text-align:right} "\
                            " .center {text-align:center} "\
                            " #wrap {min-height: 100%%;} "\
                            " #main {overflow:auto; padding-bottom:50px;} "\
                            " /*Opera Fix*/body:before {content:\"\";height:100%%;float:left;width:0;margin-top:-32767px;} "\
                            " #footer {position: relative;margin-top: -50px; height: 50px; clear:both; font-size:11px;color:#777;text-align:center;} "\
                            " #footer a {color:#333;} #footer a:hover {text-decoration: none;} "\
                            " #nav {background:#ddd;font:normal normal normal 14px/0px 'HelveticaNeue', Helvetica;} "\
                            " #nav td {padding:5px 10px;} "\
                            " #header {margin-bottom:30px;background:#EFF7FF} "\
                            " #nav, #header {border-bottom:1px solid #ccc;} "\
                            " #header-row {width:95%%;} "\
                            " #header-row th {padding:30px 10px 10px 10px;font-size:120%%;} "\
                            " #header-row td {padding:3px 10px;} "\
                            " #header-row .first {min-width:200px;width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;} "\
                            " #status-table {width:95%%;} "\
                            " #status-table th {text-align:left;background:#edf5ff;font-weight:normal;} "\
                            " #status-table th, #status-table td, #status-table tr {border:1px solid #ccc;padding:5px;} "\
                            " #buttons {font-size:20px; margin:40px 0 20px 0;} "\
                            " #buttons td {padding-right:50px;} "\
                            " #buttons input {font-size:18px;padding:5px;} "\
                            "</style>"\
                            "<meta HTTP-EQUIV='REFRESH' CONTENT=%d> "\
                            "<meta HTTP-EQUIV='Expires' Content=0> "\
                            "<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'> "\
                            "<meta charset='UTF-8'>" \
                            "<link rel='shortcut icon' href='favicon.ico'>"\
                            "</head>"\
                            "<body><div id='wrap'><div id='main'>" \
                            "<table id='nav' width='100%%'>"\
                            "  <tr>"\
                            "    <td width='20%%'><a href='.'>Home</a>&nbsp;&gt;&nbsp;<a href='%s'>%s</a></td>"\
                            "    <td width='60%%' style='text-align:center;'>Use <a href='https://mmonit.com/'>M/Monit</a> to manage all your Monit instances</td>"\
                            "    <td width='20%%'><p class='right'><a href='_about'>Monit %s</a></td>"\
                            "  </tr>"\
                            "</table>"\
                            "<center>",
                            StringBuffer_toString(system_htmlescaped), refresh, path, name, VERSION);
        StringBuffer_free(&system_htmlescaped);
}


static void do_foot(HttpResponse res) {
        StringBuffer_append(res->outputbuffer,
                            "</center></div></div>"
                            "<div id='footer'>"
                            "Copyright &copy; 2001-2024 <a href=\"https://tildeslash.com/\">Tildeslash</a>. All rights reserved. "
                            "<span style='margin-left:5px;'></span>"
                            "<a href=\"https://mmonit.com/monit/\">Monit web site</a> | "
                            "<a href=\"https://mmonit.com/wiki/\">Monit Wiki</a> | "
                            "<a href=\"https://mmonit.com/\">M/Monit</a>"
                            "</div></body></html>");
}


static void do_home(HttpResponse res) {
        do_head(res, "", "", Run.polltime);
        StringBuffer_T system_htmlescaped = escapeHTML(StringBuffer_create(16), Run.system->name);
        StringBuffer_append(res->outputbuffer,
                            "<table id='header' width='100%%'>"
                            " <tr>"
                            "  <td colspan=2 valign='top' class='left' width='100%%'>"
                            "  <h1>Monit Service Manager</h1>"
                            "  <p class='center'>Monit is <a href='_runtime'>running</a> on %s and monitoring:</p><br>"
                            "  </td>"
                            " </tr>"
                            "</table>",
                            StringBuffer_toString(system_htmlescaped));
        StringBuffer_free(&system_htmlescaped);

        do_home_system(res);
        do_home_process(res);
        do_home_program(res);
        do_home_filesystem(res);
        do_home_file(res);
        do_home_fifo(res);
        do_home_directory(res);
        do_home_net(res);
        do_home_host(res);

        do_foot(res);
}


static void do_about(HttpResponse res) {
        StringBuffer_append(res->outputbuffer,
                            "<html><head><title>about monit</title></head><body bgcolor=white>"
                            "<br><h1><center><a href='https://mmonit.com/monit/'>"
                            "monit " VERSION "</a></center></h1>");
        StringBuffer_append(res->outputbuffer,
                            "<ul>"
                            "<li style='padding-bottom:10px;'>Copyright &copy; 2001-2024 <a "
                            "href='https://tildeslash.com/'>Tildeslash Ltd"
                            "</a>. All Rights Reserved.</li></ul>");
        StringBuffer_append(res->outputbuffer, "<hr size='1'>");
        StringBuffer_append(res->outputbuffer,
                            "<p>This program is free software; you can redistribute it and/or "
                            "modify it under the terms of the GNU Affero General Public License version 3</p>"
                            "<p>This program is distributed in the hope that it will be useful, but "
                            "WITHOUT ANY WARRANTY; without even the implied warranty of "
                            "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the "
                            "<a href='https://www.gnu.org/licenses/agpl.html'>"
                            "GNU AFFERO GENERAL PUBLIC LICENSE</a> for more details.</p>");
        StringBuffer_append(res->outputbuffer,
                            "<center><p style='padding-top:20px;'>[<a href='.'>Back to Monit</a>]</p></body></html>");
}


static void do_ping(HttpResponse res) {
        StringBuffer_append(res->outputbuffer, "pong");
}


static void do_getid(HttpResponse res) {
        escapeHTML(res->outputbuffer, Run.id);
}


static void do_runtime(HttpRequest req, HttpResponse res) {
        int pid = exist_daemon();
        char buf[STRLEN];

        do_head(res, "_runtime", "Runtime", 1000);
        StringBuffer_append(res->outputbuffer,
                            "<h2>Monit runtime status</h2>");
        StringBuffer_append(res->outputbuffer, "<table id='status-table'><tr>"
                            "<th width='40%%'>Parameter</th>"
                            "<th width='60%%'>Value</th></tr>");
        _displayTableRow(res, true,  NULL, "Monit ID",                     "%s", Run.id);
        _displayTableRow(res, true,  NULL, "Host",                         "%s", Run.system->name);
        _displayTableRow(res, false, NULL, "Process id",                   "%d", pid);
        _displayTableRow(res, true,  NULL, "Effective user running Monit", "%s", Run.Env.user);
        _displayTableRow(res, true,  NULL, "Controlfile",                  "%s", Run.files.control);
        if (Run.files.log)
                _displayTableRow(res, true, NULL, "Logfile", "%s", Run.files.log);
        _displayTableRow(res, true, NULL, "Pidfile",    "%s", Run.files.pid);
        _displayTableRow(res, true, NULL, "State file", "%s", Run.files.state);
        _displayTableRow(res, true, NULL, "Debug",      "%s", Run.debug ? "True" : "False");
        _displayTableRow(res, true, NULL, "Log",        "%s", (Run.flags & Run_Log) ? "True" : "False");
        _displayTableRow(res, true, NULL, "Use syslog", "%s", (Run.flags & Run_UseSyslog) ? "True" : "False");

        if (Run.eventlist_dir) {
                if (Run.eventlist_slots < 0)
                        _displayTableRow(res, true, NULL, "Event queue", "base directory %s with unlimited slots", Run.eventlist_dir);
                else
                        _displayTableRow(res, true, NULL, "Event queue", "base directory %s with %d slots", Run.eventlist_dir, Run.eventlist_slots);
        }
#ifdef HAVE_OPENSSL
        {
                char opt[STRLEN] = {};
                const char *options = Ssl_printOptions(&(Run.ssl), opt, STRLEN);
                if (options && *options)
                        _displayTableRow(res, true, NULL, "SSL options", "%s", options);
        }
#endif
        if (Run.mmonits) {
                StringBuffer_append(res->outputbuffer, "<tr><td>M/Monit server(s)</td><td>");
                for (Mmonit_T c = Run.mmonits; c; c = c->next) {
                        escapeHTML(res->outputbuffer, c->url->url);
                        StringBuffer_append(res->outputbuffer, "<br>&nbsp;&nbsp;with timeout %s<br>", Fmt_time2str(c->timeout, (char[11]){}));
#ifdef HAVE_OPENSSL
                        if (c->ssl.flags) {
                                StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;using TLS");
                                const char *options = Ssl_printOptions(&c->ssl, (char[STRLEN]){}, STRLEN);
                                if (options && *options)
                                        StringBuffer_append(res->outputbuffer, " with options {%s}", options);
                                if (c->ssl.checksum) {
                                        StringBuffer_append(res->outputbuffer, " and certificate checksum %s equal to '", Checksum_Names[c->ssl.checksumType]);
                                        escapeHTML(res->outputbuffer, c->ssl.checksum);
                                        StringBuffer_append(res->outputbuffer, "'");
                                }
                                StringBuffer_append(res->outputbuffer, "<br>");
                        }
#endif
                        if (Run.flags & Run_MmonitCredentials && c->url->user)
                                StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;with credentials<br>");
                        if (c->hostgroups) {
                                for (_list_t g = c->hostgroups->head; g; g = g->next) {
                                        StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;hostgroup \"%s\"<br>", (const char *)g->e);
                                }
                        }
                        if (c->next)
                                StringBuffer_append(res->outputbuffer, "</td></tr><tr><td>&nbsp;</td><td>");
                }
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
        if (Run.mailservers) {
                StringBuffer_append(res->outputbuffer, "<tr><td>Mail server(s)</td><td>");
                for (MailServer_T mta = Run.mailservers; mta; mta = mta->next) {
                        escapeHTML(res->outputbuffer, mta->host);
                        StringBuffer_append(res->outputbuffer, ":%d", mta->port);
#ifdef HAVE_OPENSSL
                        if (mta->ssl.flags) {
                                StringBuffer_append(res->outputbuffer, " using TLS");
                                char opt[STRLEN] = {};
                                const char *options = Ssl_printOptions(&mta->ssl, opt, STRLEN);
                                if (options && *options)
                                        StringBuffer_append(res->outputbuffer, " with options {%s}", options);
                                if (mta->ssl.checksum) {
                                        StringBuffer_append(res->outputbuffer, " and certificate checksum %s equal to '", Checksum_Names[mta->ssl.checksumType]);
                                        escapeHTML(res->outputbuffer, mta->ssl.checksum);
                                        StringBuffer_append(res->outputbuffer, "'");
                                }
                        }
#endif
                        if (mta->next)
                                StringBuffer_append(res->outputbuffer, "</td></tr><tr><td>&nbsp;</td><td>");
                }
                StringBuffer_append(res->outputbuffer, "</td></tr>");
        }
        if (Run.MailFormat.from)
                _formatAddress(res, "from", Run.MailFormat.from);
        if (Run.MailFormat.replyto)
                _formatAddress(res, "reply to", Run.MailFormat.replyto);
        if (Run.MailFormat.subject)
                _displayTableRow(res, true, NULL, "Default mail subject", "%s", Run.MailFormat.subject);
        if (Run.MailFormat.message)
                _displayTableRow(res, true, NULL, "Default mail message", "%s", Run.MailFormat.message);
        _displayTableRow(res, false, NULL, "Limit for Send/Expect buffer",      "%s", Fmt_bytes2str(Run.limits.sendExpectBuffer, buf));
        _displayTableRow(res, false, NULL, "Limit for file content buffer",     "%s", Fmt_bytes2str(Run.limits.fileContentBuffer, buf));
        _displayTableRow(res, false, NULL, "Limit for HTTP content buffer",     "%s", Fmt_bytes2str(Run.limits.httpContentBuffer, buf));
        _displayTableRow(res, false, NULL, "Limit for program output",          "%s", Fmt_bytes2str(Run.limits.programOutput, buf));
        _displayTableRow(res, false, NULL, "Limit for network timeout",         "%s", Fmt_time2str(Run.limits.networkTimeout, (char[11]){}));
        _displayTableRow(res, false, NULL, "Limit for check program timeout",   "%s", Fmt_time2str(Run.limits.programTimeout, (char[11]){}));
        _displayTableRow(res, false, NULL, "Limit for service stop timeout",    "%s", Fmt_time2str(Run.limits.stopTimeout, (char[11]){}));
        _displayTableRow(res, false, NULL, "Limit for service start timeout",   "%s", Fmt_time2str(Run.limits.startTimeout, (char[11]){}));
        _displayTableRow(res, false, NULL, "Limit for service restart timeout", "%s", Fmt_time2str(Run.limits.restartTimeout, (char[11]){}));
        _displayTableRow(res, false, NULL, "Limit for test action exec timeout","%s", Fmt_time2str(Run.limits.execTimeout, (char[11]){}));
        _displayTableRow(res, false, NULL, "On reboot",                         "%s", onReboot_Names[Run.onreboot]);
        _displayTableRow(res, false, NULL, "Poll time",                         "%d seconds with start delay %d seconds", Run.polltime, Run.startdelay);
        if (Run.httpd.flags & Httpd_Net) {
                _displayTableRow(res, true,  NULL, "httpd bind address", "%s", Run.httpd.socket.net.address ? Run.httpd.socket.net.address : "Any/All");
                _displayTableRow(res, false, NULL, "httpd portnumber",   "%d", Run.httpd.socket.net.port);
                _displayTableRow(res, false, NULL, "httpd net readonly", "%s", Run.httpd.socket.net.readonly ? "True" : "False");
#ifdef HAVE_OPENSSL
                const char *options = Ssl_printOptions(&(Run.httpd.socket.net.ssl), (char[STRLEN]){}, STRLEN);
                if (options && *options)
                        _displayTableRow(res, false, NULL, "httpd encryption", "%s", options);
#endif
        }
        if (Run.httpd.flags & Httpd_Unix) {
                _displayTableRow(res, true, NULL, "httpd unix socket", "%s", Run.httpd.socket.unix.path);
                _displayTableRow(res, false, NULL, "httpd unix readonly", "%s", Run.httpd.socket.unix.readonly ? "True" : "False");
        }
        _displayTableRow(res, false, NULL, "httpd signature",           "%s", Run.httpd.flags & Httpd_Signature ? "True" : "False");
        _displayTableRow(res, false, NULL, "httpd auth. style",         "%s", Run.httpd.credentials && Engine_hasAllow() ?
                                                               "Basic Authentication and Host/Net allow list" : Run.httpd.credentials ? "Basic Authentication" : Engine_hasAllow() ? "Host/Net allow list" : "No authentication");
        print_alerts(res, Run.maillist);
        StringBuffer_append(res->outputbuffer, "</table>");
        if (! is_readonly(req)) {
                StringBuffer_append(res->outputbuffer,
                                    "<table id='buttons'><tr>");
                StringBuffer_append(res->outputbuffer,
                                    "<td style='color:red;'>"
                                    "<form method=POST action='_runtime'>Stop Monit http server? "
                                    "<input type=hidden name='securitytoken' value='%s'>"
                                    "<input type=hidden name='action' value='stop'>"
                                    "<input type=submit value='Go'>"
                                    "</form>"
                                    "</td>",
                                    res->token);
                StringBuffer_append(res->outputbuffer,
                                    "<td>"
                                    "<form method=POST action='_runtime'>Force validate now? "
                                    "<input type=hidden name='securitytoken' value='%s'>"
                                    "<input type=hidden name='action' value='validate'>"
                                    "<input type=submit value='Go'>"
                                    "</form>"
                                    "</td>",
                                    res->token);

                if ((Run.flags & Run_Log) && ! (Run.flags & Run_UseSyslog)) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td>"
                                            "<form method=POST action='_viewlog'>View Monit logfile? "
                                            "<input type=hidden name='securitytoken' value='%s'>"
                                            "<input type=submit value='Go'>"
                                            "</form>"
                                            "</td>",
                                            res->token);
                }
                StringBuffer_append(res->outputbuffer,
                                    "</tr></table>");
        }
        do_foot(res);
}


static void do_viewlog(HttpRequest req, HttpResponse res) {
        if (is_readonly(req)) {
                send_error(req, res, SC_FORBIDDEN, "You do not have sufficient privileges to access this page");
                return;
        }
        do_head(res, "_viewlog", "View log", 100);
        if ((Run.flags & Run_Log) && ! (Run.flags & Run_UseSyslog)) {
                FILE *f = fopen(Run.files.log, "r");
                if (f) {
                        size_t n;
                        size_t total = 0;
                        char buf[512];
                        StringBuffer_append(res->outputbuffer, "<br><p><form><textarea cols=120 rows=30 readonly>");
                        while (total < VIEWLOG_LIMIT && (n = fread(buf, sizeof(char), sizeof(buf) - 1, f)) > 0) {
                                total += n;
                                buf[n] = 0;
                                escapeHTML(res->outputbuffer, buf);
                        }
                        fclose(f);
                        StringBuffer_append(res->outputbuffer, "</textarea></form>");
                } else {
                        StringBuffer_append(res->outputbuffer, "Error opening logfile: %s", STRERROR);
                }
        } else {
                StringBuffer_append(res->outputbuffer,
                                    "<b>Cannot view logfile:</b><br>");
                if (! (Run.flags & Run_Log))
                        StringBuffer_append(res->outputbuffer, "Monit was started without logging");
                else
                        StringBuffer_append(res->outputbuffer, "Monit uses syslog");
        }
        do_foot(res);
}


static void handle_service(HttpRequest req, HttpResponse res) {
        char *name = req->url;
        if (! name) {
                send_error(req, res, SC_NOT_FOUND, "Service name required");
                return;
        }
        Service_T s = Util_getService(++name);
        if (! s) {
                send_error(req, res, SC_NOT_FOUND, "There is no service named \"%s\"", name);
                return;
        }
        do_service(req, res, s);
}


// Do action for the service (the service name is the last component of the URL path)
static void handle_service_action(HttpRequest req, HttpResponse res) {
        char *name = req->url;
        if (! name) {
                send_error(req, res, SC_NOT_FOUND, "Service name required");
                return;
        }
        struct ServiceMap_T ap = {.found = 0, .data.action.name = get_parameter(req, "action")};
        if (ap.data.action.name) {
                if (is_readonly(req)) {
                        send_error(req, res, SC_FORBIDDEN, "You do not have sufficient privileges to access this page");
                } else {
                        ap.data.action.id = Util_getAction(ap.data.action.name);
                        if (ap.data.action.id == Action_Ignored) {
                                send_error(req, res, SC_BAD_REQUEST, "Invalid action \"%s\"", ap.data.action.name);
                        } else {
                                Service_T s = Util_getService(++name);
                                if (! s) {
                                        send_error(req, res, SC_NOT_FOUND, "There is no service named \"%s\"", name);
                                        return;
                                }
                                _serviceMapAction(s, &ap);
                                Run.flags |= Run_ActionPending; /* set the global flag */
                                do_wakeupcall();
                                do_service(req, res, s);
                        }
                }
        }
}


// Do action for all services listed in "service" HTTP parameter (may have multiple value)
static void handle_doaction(HttpRequest req, HttpResponse res) {
        struct ServiceMap_T ap = {.found = 0, .data.action.name = get_parameter(req, "action")};
        if (ap.data.action.name) {
                if (is_readonly(req)) {
                        send_error(req, res, SC_FORBIDDEN, "You do not have sufficient privileges to access this page");
                        return;
                } else {
                        if ((ap.data.action.id = Util_getAction(ap.data.action.name)) == Action_Ignored) {
                                send_error(req, res, SC_BAD_REQUEST, "Invalid action \"%s\"", ap.data.action.name);
                                return;
                        }
                        for (HttpParameter p = req->params; p; p = p->next) {
                                if (IS(p->name, "service")) {
                                        _serviceMapByName(p->value, _serviceMapAction, &ap);
                                        if (ap.found == 0) {
                                                send_error(req, res, SC_BAD_REQUEST, "There is no service named \"%s\"", p->value ? p->value : "");
                                                return;
                                        }
                                }
                        }
                        if (ap.found > 0) {
                                Run.flags |= Run_ActionPending;
                                do_wakeupcall();
                        }
                }
        }
}


static void handle_runtime(HttpRequest req, HttpResponse res) {
        LOCK(Run.mutex)
        do_runtime(req, res);
        END_LOCK;
}


static void handle_runtime_action(HttpRequest req, HttpResponse res) {
        const char *action = get_parameter(req, "action");
        if (action) {
                if (is_readonly(req)) {
                        send_error(req, res, SC_FORBIDDEN, "You do not have sufficient privileges to access this page");
                        return;
                }
                if (IS(action, "validate")) {
                        Log_info("The Monit http server woke up on user request\n");
                        do_wakeupcall();
                } else if (IS(action, "stop")) {
                        Log_info("The Monit http server stopped on user request\n");
                        send_error(req, res, SC_SERVICE_UNAVAILABLE, "The Monit http server is stopped");
                        Engine_stop();
                        return;
                }
        }
        handle_runtime(req, res);
}


static void do_service(HttpRequest req, HttpResponse res, Service_T s) {
        assert(s);
        char buf[STRLEN] = {};

        do_head(res, s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped), Run.polltime);
        StringBuffer_append(res->outputbuffer,
                            "<h2>%s status</h2>"
                            "<table id='status-table'>"
                            "<tr>"
                            "<th width='30%%'>Parameter</th>"
                            "<th width='70%%'>Value</th>"
                            "</tr>",
                            Servicetype_Names[s->type]);
        _displayTableRow(res, true, NULL, "Name", "%s", s->name);
        if (s->type == Service_Process)
                _displayTableRow(res, true, NULL, s->matchlist ? "Match" : "Pid file", "%s", s->path);
        else if (s->type == Service_Host)
                _displayTableRow(res, true, NULL, "Address", "%s", s->path);
        else if (s->type == Service_Net)
                _displayTableRow(res, true, NULL, "Interface", "%s", s->path);
        else if (s->type != Service_System)
                _displayTableRow(res, true, NULL, "Path", "%s", s->path);
        _displayTableRow(res, false, NULL, "Status", "%s", get_service_status(HTML, s, buf, sizeof(buf)));
        for (ServiceGroup_T sg = Service_Group_List; sg; sg = sg->next) {
                for (_list_t m = sg->members->head; m; m = m->next)
                        if (m->e == s)
                                _displayTableRow(res, false, NULL, "Group", "%s",  sg->name);
        }
        _displayTableRow(res, false, NULL, "Monitoring status", "%s", get_monitoring_status(HTML, s, buf, sizeof(buf)));
        _displayTableRow(res, false, NULL, "Monitoring mode",   "%s", Mode_Names[s->mode]);
        _displayTableRow(res, false, NULL, "On reboot",         "%s", onReboot_Names[s->onreboot]);
        for (Dependant_T d = s->dependantlist; d; d = d->next) {
                if (d->dependant != NULL)
                        _displayTableRow(res, false, NULL, "Depends on service", "<a href='%s'>%s</a>", d->dependant_urlescaped, StringBuffer_toString(d->dependant_htmlescaped));
        }
        if (s->start)
                _formatAction(res, "Start", s->start);
        if (s->stop)
                _formatAction(res, "Stop", s->stop);
        if (s->restart)
                _formatAction(res, "Restart", s->restart);
        if (s->every.type != Every_Cycle) {
                if (s->every.type == Every_SkipCycles)
                        _displayTableRow(res, false, NULL, "Check service", "every %d cycle", s->every.spec.cycle.number);
                else if (s->every.type == Every_Cron)
                        _displayTableRow(res, false, NULL, "Check service", "every <code>\"%s\"</code>", s->every.spec.cron);
                else if (s->every.type == Every_NotInCron)
                        _displayTableRow(res, false, NULL, "Check service", "not every <code>\"%s\"</code>", s->every.spec.cron);
        }
        _printStatus(HTML, res, s);
        // Rules
        print_service_rules_timeout(res, s);
        print_service_rules_nonexistence(res, s);
        print_service_rules_existence(res, s);
        print_service_rules_icmp(res, s);
        print_service_rules_port(res, s);
        print_service_rules_socket(res, s);
        print_service_rules_perm(res, s);
        print_service_rules_uid(res, s);
        print_service_rules_euid(res, s);
        print_service_rules_secattr(res, s);
        print_service_rules_filedescriptors(res, s);
        print_service_rules_gid(res, s);
        print_service_rules_timestamp(res, s);
        print_service_rules_fsflags(res, s);
        print_service_rules_filesystem(res, s);
        print_service_rules_size(res, s);
        print_service_rules_nlink(res, s);
        print_service_rules_linkstatus(res, s);
        print_service_rules_linkspeed(res, s);
        print_service_rules_linksaturation(res, s);
        print_service_rules_uploadbytes(res, s);
        print_service_rules_uploadpackets(res, s);
        print_service_rules_downloadbytes(res, s);
        print_service_rules_downloadpackets(res, s);
        print_service_rules_uptime(res, s);
        print_service_rules_content(res, s);
        print_service_rules_checksum(res, s);
        print_service_rules_pid(res, s);
        print_service_rules_ppid(res, s);
        print_service_rules_program(res, s);
        print_service_rules_resource(res, s);
        print_alerts(res, s->maillist);
        StringBuffer_append(res->outputbuffer, "</table>");
        print_buttons(req, res, s);
        do_foot(res);
}


static void do_home_system(HttpResponse res) {
        Service_T s = Run.system;
        char buf[STRLEN];

        StringBuffer_append(res->outputbuffer,
                            "<table id='header-row'>"
                            "<tr>"
                            "<th class='left first'>System</th>"
                            "<th class='left'>Status</th>"
                            "<th class='right column'>Load</th>"
                            "<th class='right column'>CPU</th>"
                            "<th class='right column'>Memory</th>"
                            "<th class='right column'>Swap</th>"
                            "</tr>"
                            "<tr class='stripe'>"
                            "<td class='left'><a href='%s'>%s</a></td>"
                            "<td class='left'>%s</td>"
                            "<td class='right column'>[%.2f]&nbsp;[%.2f]&nbsp;[%.2f]</td>"
                            "<td class='right column'>",
                            s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped),
                            get_service_status(HTML, s, buf, sizeof(buf)),
                            System_Info.loadavg[0], System_Info.loadavg[1], System_Info.loadavg[2]);
        if (System_Info.statisticsAvailable & Statistics_CpuUser)
                StringBuffer_append(res->outputbuffer, "%.1f%%us&nbsp;", System_Info.cpu.usage.user > 0. ? System_Info.cpu.usage.user : 0.);
        if (System_Info.statisticsAvailable & Statistics_CpuSystem)
                StringBuffer_append(res->outputbuffer, "%.1f%%sy&nbsp;", System_Info.cpu.usage.system > 0. ? System_Info.cpu.usage.system : 0.);
        if (System_Info.statisticsAvailable & Statistics_CpuNice)
                StringBuffer_append(res->outputbuffer, "%.1f%%ni&nbsp;", System_Info.cpu.usage.nice > 0. ? System_Info.cpu.usage.nice : 0.);
        if (System_Info.statisticsAvailable & Statistics_CpuIOWait)
                StringBuffer_append(res->outputbuffer, "%.1f%%wa&nbsp;", System_Info.cpu.usage.iowait > 0. ? System_Info.cpu.usage.iowait : 0.);
        StringBuffer_append(res->outputbuffer,
                            "</td>");
        StringBuffer_append(res->outputbuffer,
                            "<td class='right column'>%.1f%% [%s]</td>",
                            System_Info.memory.usage.percent, Fmt_bytes2str(System_Info.memory.usage.bytes, buf));
        StringBuffer_append(res->outputbuffer,
                            "<td class='right column'>%.1f%% [%s]</td>",
                            System_Info.swap.usage.percent, Fmt_bytes2str(System_Info.swap.usage.bytes, buf));
        StringBuffer_append(res->outputbuffer,
                            "</tr>"
                            "</table>");
}


static void do_home_process(HttpResponse res) {
        char      buf[STRLEN];
        bool on = true;
        bool header = true;

        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                if (s->type != Service_Process)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th class='left' class='first'>Process</th>"
                                            "<th class='left'>Status</th>"
                                            "<th class='right'>Uptime</th>"
                                            "<th class='right'>CPU Total</b></th>"
                                            "<th class='right'>Memory Total</th>"
                                            "<th class='right column'>Read</th>"
                                            "<th class='right column'>Write</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr%s>"
                                    "<td class='left'><a href='%s'>%s</a></td>"
                                    "<td class='left'>%s</td>",
                                    on ? " class='stripe'" : "",
                                    s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped),
                                    get_service_status(HTML, s, buf, sizeof(buf)));
                if (! (Run.flags & Run_ProcessEngineEnabled) || ! Util_hasServiceStatus(s) || s->inf.process->uptime < 0) {
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                } else {
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%s</td>", _getUptime(s->inf.process->uptime, (char[256]){}));
                }
                if (! (Run.flags & Run_ProcessEngineEnabled) || ! Util_hasServiceStatus(s) || s->inf.process->total_cpu_percent < 0) {
                                StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                } else {
                        StringBuffer_append(res->outputbuffer, "<td class='right%s'>%.1f%%</td>", (s->error & Event_Resource) ? " red-text" : "", s->inf.process->total_cpu_percent);
                }
                if (! (Run.flags & Run_ProcessEngineEnabled) || ! Util_hasServiceStatus(s) || s->inf.process->total_mem_percent < 0) {
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                } else {
                        StringBuffer_append(res->outputbuffer, "<td class='right%s'>%.1f%% [%s]</td>", (s->error & Event_Resource) ? " red-text" : "", s->inf.process->total_mem_percent, Fmt_bytes2str(s->inf.process->total_mem, buf));
                }
                bool hasReadBytes = Statistics_initialized(&(s->inf.process->read.bytes));
                bool hasReadOperations = Statistics_initialized(&(s->inf.process->read.operations));
                if (! (Run.flags & Run_ProcessEngineEnabled) || ! Util_hasServiceStatus(s) || (! hasReadBytes && ! hasReadOperations)) {
                        StringBuffer_append(res->outputbuffer, "<td class='right column'>-</td>");
                } else if (hasReadBytes) {
                        StringBuffer_append(res->outputbuffer, "<td class='right column%s'>%s/s</td>", (s->error & Event_Resource) ? " red-text" : "", Fmt_bytes2str(Statistics_deltaNormalize(&(s->inf.process->read.bytes)), (char[10]){}));
                } else if (hasReadOperations) {
                        StringBuffer_append(res->outputbuffer, "<td class='right column%s'>%.1f/s</td>", (s->error & Event_Resource) ? " red-text" : "", Statistics_deltaNormalize(&(s->inf.process->read.operations)));
                }
                bool hasWriteBytes = Statistics_initialized(&(s->inf.process->write.bytes));
                bool hasWriteOperations = Statistics_initialized(&(s->inf.process->write.operations));
                if (! (Run.flags & Run_ProcessEngineEnabled) || ! Util_hasServiceStatus(s) || (! hasWriteBytes && ! hasWriteOperations)) {
                        StringBuffer_append(res->outputbuffer, "<td class='right column'>-</td>");
                } else if (hasWriteBytes) {
                        StringBuffer_append(res->outputbuffer, "<td class='right column%s'>%s/s</td>", (s->error & Event_Resource) ? " red-text" : "", Fmt_bytes2str(Statistics_deltaNormalize(&(s->inf.process->write.bytes)), (char[10]){}));
                } else if (hasWriteOperations) {
                        StringBuffer_append(res->outputbuffer, "<td class='right column%s'>%.1f/s</td>", (s->error & Event_Resource) ? " red-text" : "", Statistics_deltaNormalize(&(s->inf.process->write.operations)));
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_program(HttpResponse res) {
        char buf[STRLEN];
        bool on = true;
        bool header = true;

        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                if (s->type != Service_Program)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th class='left' class='first'>Program</th>"
                                            "<th class='left'>Status</th>"
                                            "<th class='left'>Output</th>"
                                            "<th class='right'>Last started</th>"
                                            "<th class='right'>Exit value</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td class='left'><a href='%s'>%s</a></td>"
                                    "<td class='left'>%s</td>",
                                    on ? "class='stripe'" : "",
                                    s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped),
                                    get_service_status(HTML, s, buf, sizeof(buf)));
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer, "<td class='left'>-</td>");
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                } else {
                        if (s->program->started) {
                                StringBuffer_append(res->outputbuffer, "<td class='left short'>");
                                if (StringBuffer_length(s->program->lastOutput)) {
                                        // Print first line only (escape HTML characters if any)
                                        const char *output = StringBuffer_toString(s->program->lastOutput);
                                        for (int i = 0; output[i]; i++) {
                                                if (output[i] == '<')
                                                        StringBuffer_append(res->outputbuffer, "&lt;");
                                                else if (output[i] == '>')
                                                        StringBuffer_append(res->outputbuffer, "&gt;");
                                                else if (output[i] == '&')
                                                        StringBuffer_append(res->outputbuffer, "&amp;");
                                                else if (output[i] == '\r' || output[i] == '\n')
                                                        break;
                                                else
                                                        StringBuffer_append(res->outputbuffer, "%c", output[i]);
                                        }
                                } else {
                                        StringBuffer_append(res->outputbuffer, "no output");
                                }
                                StringBuffer_append(res->outputbuffer, "</td>");
                                StringBuffer_append(res->outputbuffer, "<td class='right'>%s</td>", Time_fmt((char[32]){}, 32, "%d %b %Y %H:%M:%S", s->program->started));
                                StringBuffer_append(res->outputbuffer, "<td class='right'>%d</td>", s->program->exitStatus);
                        } else {
                                StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                                StringBuffer_append(res->outputbuffer, "<td class='right'>Not yet started</td>");
                                StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                        }
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");

}


static void do_home_net(HttpResponse res) {
        char buf[STRLEN];
        bool on = true;
        bool header = true;

        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                if (s->type != Service_Net)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th class='left first'>Net</th>"
                                            "<th class='left'>Status</th>"
                                            "<th class='right'>Upload</th>"
                                            "<th class='right'>Download</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td class='left'><a href='%s'>%s</a></td>"
                                    "<td class='left'>%s</td>",
                                    on ? "class='stripe'" : "",
                                    s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped),
                                    get_service_status(HTML, s, buf, sizeof(buf)));
                if (! Util_hasServiceStatus(s) || Link_getState(s->inf.net->stats) != 1) {
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                } else {
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%s&#47;s</td>", Fmt_bytes2str(Link_getBytesOutPerSecond(s->inf.net->stats), buf));
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%s&#47;s</td>", Fmt_bytes2str(Link_getBytesInPerSecond(s->inf.net->stats), buf));
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_filesystem(HttpResponse res) {
        char buf[STRLEN];
        bool on = true;
        bool header = true;

        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                if (s->type != Service_Filesystem)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th class='left first'>Filesystem</th>"
                                            "<th class='left'>Status</th>"
                                            "<th class='right'>Space usage</th>"
                                            "<th class='right'>Inodes usage</th>"
                                            "<th class='right column'>Read</th>"
                                            "<th class='right column'>Write</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td class='left'><a href='%s'>%s</a></td>"
                                    "<td class='left'>%s</td>",
                                    on ? "class='stripe'" : "",
                                    s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped),
                                    get_service_status(HTML, s, buf, sizeof(buf)));
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td class='right'>- [-]</td>"
                                            "<td class='right'>- [-]</td>"
                                            "<td class='right column'>- [-]</td>"
                                            "<td class='right column'>- [-]</td>");
                } else {
                        StringBuffer_append(res->outputbuffer,
                                            "<td class='right column%s'>%.1f%% [%s]</td>",
                                            (s->error & Event_Resource) ? " red-text" : "",
                                            s->inf.filesystem->space_percent,
                                            s->inf.filesystem->f_bsize > 0 ? Fmt_bytes2str(s->inf.filesystem->f_blocksused * s->inf.filesystem->f_bsize, buf) : "0 MB");
                        if (s->inf.filesystem->f_files > 0) {
                                StringBuffer_append(res->outputbuffer,
                                                    "<td class='right column%s'>%.1f%% [%lld objects]</td>",
                                                    (s->error & Event_Resource) ? " red-text" : "",
                                                    s->inf.filesystem->inode_percent,
                                                    s->inf.filesystem->f_filesused);
                        } else {
                                StringBuffer_append(res->outputbuffer,
                                                    "<td class='right column'>not supported by filesystem</td>");
                        }
                        StringBuffer_append(res->outputbuffer,
                                            "<td class='right column%s'>%s/s</td>"
                                            "<td class='right column%s'>%s/s</td>",
                                            (s->error & Event_Resource) ? " red-text" : "",
                                            Fmt_bytes2str(Statistics_deltaNormalize(&(s->inf.filesystem->read.bytes)), (char[10]){}),
                                            (s->error & Event_Resource) ? " red-text" : "",
                                            Fmt_bytes2str(Statistics_deltaNormalize(&(s->inf.filesystem->write.bytes)), (char[10]){}));
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_file(HttpResponse res) {
        char buf[STRLEN];
        bool on = true;
        bool header = true;

        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                if (s->type != Service_File)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th class='left first'>File</th>"
                                            "<th class='left'>Status</th>"
                                            "<th class='right'>Size</th>"
                                            "<th class='right'>Permission</th>"
                                            "<th class='right'>UID</th>"
                                            "<th class='right'>GID</th>"
                                            "</tr>");

                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td class='left'><a href='%s'>%s</a></td>"
                                    "<td class='left'>%s</td>",
                                    on ? "class='stripe'" : "",
                                    s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped),
                                    get_service_status(HTML, s, buf, sizeof(buf)));
                if (! Util_hasServiceStatus(s) || s->inf.file->size < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%s</td>", Fmt_bytes2str(s->inf.file->size, (char[10]){}));
                if (! Util_hasServiceStatus(s) || s->inf.file->mode < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%04o</td>", s->inf.file->mode & 07777);
                if (! Util_hasServiceStatus(s) || s->inf.file->uid < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%d</td>", s->inf.file->uid);
                if (! Util_hasServiceStatus(s) || s->inf.file->gid < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%d</td>", s->inf.file->gid);
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_fifo(HttpResponse res) {
        char buf[STRLEN];
        bool on = true;
        bool header = true;

        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                if (s->type != Service_Fifo)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th class='left first'>Fifo</th>"
                                            "<th class='left'>Status</th>"
                                            "<th class='right'>Permission</th>"
                                            "<th class='right'>UID</th>"
                                            "<th class='right'>GID</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td class='left'><a href='%s'>%s</a></td>"
                                    "<td class='left'>%s</td>",
                                    on ? "class='stripe'" : "",
                                    s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped),
                                    get_service_status(HTML, s, buf, sizeof(buf)));
                if (! Util_hasServiceStatus(s) || s->inf.fifo->mode < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%04o</td>", s->inf.fifo->mode & 07777);
                if (! Util_hasServiceStatus(s) || s->inf.fifo->uid < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%d</td>", s->inf.fifo->uid);
                if (! Util_hasServiceStatus(s) || s->inf.fifo->gid < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%d</td>", s->inf.fifo->gid);
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_directory(HttpResponse res) {
        char buf[STRLEN];
        bool on = true;
        bool header = true;

        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                if (s->type != Service_Directory)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th class='left first'>Directory</th>"
                                            "<th class='left'>Status</th>"
                                            "<th class='right'>Permission</th>"
                                            "<th class='right'>UID</th>"
                                            "<th class='right'>GID</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td class='left'><a href='%s'>%s</a></td>"
                                    "<td class='left'>%s</td>",
                                    on ? "class='stripe'" : "",
                                    s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped),
                                    get_service_status(HTML, s, buf, sizeof(buf)));
                if (! Util_hasServiceStatus(s) || s->inf.directory->mode < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%04o</td>", s->inf.directory->mode & 07777);
                if (! Util_hasServiceStatus(s) || s->inf.directory->uid < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%d</td>", s->inf.directory->uid);
                if (! Util_hasServiceStatus(s) || s->inf.directory->gid < 0)
                        StringBuffer_append(res->outputbuffer, "<td class='right'>-</td>");
                else
                        StringBuffer_append(res->outputbuffer, "<td class='right'>%d</td>", s->inf.directory->gid);
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


static void do_home_host(HttpResponse res) {
        char buf[STRLEN];
        bool on = true;
        bool header = true;

        for (Service_T s = Service_List_Conf; s; s = s->next_conf) {
                if (s->type != Service_Host)
                        continue;
                if (header) {
                        StringBuffer_append(res->outputbuffer,
                                            "<table id='header-row'>"
                                            "<tr>"
                                            "<th class='left first'>Host</th>"
                                            "<th class='left'>Status</th>"
                                            "<th class='right'>Protocol(s)</th>"
                                            "</tr>");
                        header = false;
                }
                StringBuffer_append(res->outputbuffer,
                                    "<tr %s>"
                                    "<td class='left'><a href='%s'>%s</a></td>"
                                    "<td class='left'>%s</td>",
                                    on ? "class='stripe'" : "",
                                    s->name_urlescaped, StringBuffer_toString(s->name_htmlescaped),
                                    get_service_status(HTML, s, buf, sizeof(buf)));
                if (! Util_hasServiceStatus(s)) {
                        StringBuffer_append(res->outputbuffer,
                                            "<td class='right'>-</td>");
                } else {
                        StringBuffer_append(res->outputbuffer,
                                            "<td class='right'>");
                        for (Icmp_T icmp = s->icmplist; icmp; icmp = icmp->next) {
                                if (icmp != s->icmplist)
                                        StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
                                switch (icmp->is_available) {
                                        case Connection_Init:
                                                StringBuffer_append(res->outputbuffer, "<span class='gray-text'>[Ping]</span>");
                                                break;
                                        case Connection_Failed:
                                                StringBuffer_append(res->outputbuffer, "<span class='red-text'>[Ping]</span>");
                                                break;
                                        default:
                                                StringBuffer_append(res->outputbuffer, "<span>[Ping]</span>");
                                                break;
                                }
                        }
                        if (s->icmplist && s->portlist)
                                StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
                        for (Port_T port = s->portlist; port; port = port->next) {
                                if (port != s->portlist)
                                        StringBuffer_append(res->outputbuffer, "&nbsp;&nbsp;<b>|</b>&nbsp;&nbsp;");
                                switch (port->is_available) {
                                        case Connection_Init:
                                                StringBuffer_append(res->outputbuffer, "<span class='gray-text'>[%s] at port %d</span>", port->protocol->name, port->target.net.port);
                                                break;
                                        case Connection_Failed:
                                                StringBuffer_append(res->outputbuffer, "<span class='red-text'>[%s] at port %d</span>", port->protocol->name, port->target.net.port);
                                                break;
                                        default:
                                                if (port->target.net.ssl.options.flags && port->target.net.ssl.certificate.validDays < port->target.net.ssl.certificate.minimumDays)
                                                        StringBuffer_append(res->outputbuffer, "<span class='red-text'>[%s] at port %d</span>", port->protocol->name, port->target.net.port);
                                                else
                                                        StringBuffer_append(res->outputbuffer, "<span>[%s] at port %d</span>", port->protocol->name, port->target.net.port);
                                                break;
                                }
                        }
                        StringBuffer_append(res->outputbuffer, "</td>");
                }
                StringBuffer_append(res->outputbuffer, "</tr>");
                on = ! on;
        }
        if (! header)
                StringBuffer_append(res->outputbuffer, "</table>");
}


/* ------------------------------------------------------------------------- */


static void print_alerts(HttpResponse res, Mail_T s) {
        for (Mail_T r = s; r; r = r->next) {
                _displayTableRow(res, true, NULL, "Alert mail to", "%s", r->to ? r->to : "");
                StringBuffer_append(res->outputbuffer, "<tr><td>Alert on</td><td>");
                if (r->events == Event_Null) {
                        StringBuffer_append(res->outputbuffer, "No events");
                } else if (r->events == Event_All) {
                        StringBuffer_append(res->outputbuffer, "All events");
                } else {
                        if (IS_EVENT_SET(r->events, Event_Action))
                                StringBuffer_append(res->outputbuffer, "Action ");
                        if (IS_EVENT_SET(r->events, Event_ByteIn))
                                StringBuffer_append(res->outputbuffer, "ByteIn ");
                        if (IS_EVENT_SET(r->events, Event_ByteOut))
                                StringBuffer_append(res->outputbuffer, "ByteOut ");
                        if (IS_EVENT_SET(r->events, Event_Checksum))
                                StringBuffer_append(res->outputbuffer, "Checksum ");
                        if (IS_EVENT_SET(r->events, Event_Connection))
                                StringBuffer_append(res->outputbuffer, "Connection ");
                        if (IS_EVENT_SET(r->events, Event_Content))
                                StringBuffer_append(res->outputbuffer, "Content ");
                        if (IS_EVENT_SET(r->events, Event_Data))
                                StringBuffer_append(res->outputbuffer, "Data ");
                        if (IS_EVENT_SET(r->events, Event_Exec))
                                StringBuffer_append(res->outputbuffer, "Exec ");
                        if (IS_EVENT_SET(r->events, Event_Exist))
                                StringBuffer_append(res->outputbuffer, "Exist ");
                        if (IS_EVENT_SET(r->events, Event_FsFlag))
                                StringBuffer_append(res->outputbuffer, "Fsflags ");
                        if (IS_EVENT_SET(r->events, Event_Gid))
                                StringBuffer_append(res->outputbuffer, "Gid ");
                        if (IS_EVENT_SET(r->events, Event_Instance))
                                StringBuffer_append(res->outputbuffer, "Instance ");
                        if (IS_EVENT_SET(r->events, Event_Invalid))
                                StringBuffer_append(res->outputbuffer, "Invalid ");
                        if (IS_EVENT_SET(r->events, Event_Link))
                                StringBuffer_append(res->outputbuffer, "Link ");
                        if (IS_EVENT_SET(r->events, Event_NonExist))
                                StringBuffer_append(res->outputbuffer, "Nonexist ");
                        if (IS_EVENT_SET(r->events, Event_Permission))
                                StringBuffer_append(res->outputbuffer, "Permission ");
                        if (IS_EVENT_SET(r->events, Event_PacketIn))
                                StringBuffer_append(res->outputbuffer, "PacketIn ");
                        if (IS_EVENT_SET(r->events, Event_PacketOut))
                                StringBuffer_append(res->outputbuffer, "PacketOut ");
                        if (IS_EVENT_SET(r->events, Event_Pid))
                                StringBuffer_append(res->outputbuffer, "PID ");
                        if (IS_EVENT_SET(r->events, Event_Icmp))
                                StringBuffer_append(res->outputbuffer, "Ping ");
                        if (IS_EVENT_SET(r->events, Event_PPid))
                                StringBuffer_append(res->outputbuffer, "PPID ");
                        if (IS_EVENT_SET(r->events, Event_Resource))
                                StringBuffer_append(res->outputbuffer, "Resource ");
                        if (IS_EVENT_SET(r->events, Event_Saturation))
                                StringBuffer_append(res->outputbuffer, "Saturation ");
                        if (IS_EVENT_SET(r->events, Event_Size))
                                StringBuffer_append(res->outputbuffer, "Size ");
                        if (IS_EVENT_SET(r->events, Event_Speed))
                                StringBuffer_append(res->outputbuffer, "Speed ");
                        if (IS_EVENT_SET(r->events, Event_Status))
                                StringBuffer_append(res->outputbuffer, "Status ");
                        if (IS_EVENT_SET(r->events, Event_Timeout))
                                StringBuffer_append(res->outputbuffer, "Timeout ");
                        if (IS_EVENT_SET(r->events, Event_Timestamp))
                                StringBuffer_append(res->outputbuffer, "Timestamp ");
                        if (IS_EVENT_SET(r->events, Event_Uid))
                                StringBuffer_append(res->outputbuffer, "Uid ");
                        if (IS_EVENT_SET(r->events, Event_Uptime))
                                StringBuffer_append(res->outputbuffer, "Uptime ");
                }
                StringBuffer_append(res->outputbuffer, "</td></tr>");
                if (r->reminder)
                        _displayTableRow(res, false, NULL, "Alert reminder", "%u cycles", r->reminder);
        }
}


static void print_buttons(HttpRequest req, HttpResponse res, Service_T s) {
        if (is_readonly(req)) {
                 // A read-only REMOTE_USER does not get access to these buttons
                return;
        }
        StringBuffer_append(res->outputbuffer, "<table id='buttons'><tr>");
        /* Start program */
        if (s->start)
                StringBuffer_append(res->outputbuffer,
                                    "<td>"
                                    "<form method=POST action=%s>"
                                    "<input type=hidden name='securitytoken' value='%s'>"
                                    "<input type=hidden value='start' name=action>"
                                    "<input type=submit value='Start service'>"
                                    "</form>"
                                    "</td>", s->name_urlescaped, res->token);
        /* Stop program */
        if (s->stop)
                StringBuffer_append(res->outputbuffer,
                                    "<td>"
                                    "<form method=POST action=%s>"
                                    "<input type=hidden name='securitytoken' value='%s'>"
                                    "<input type=hidden value='stop' name=action>"
                                    "<input type=submit value='Stop service'>"
                                    "</form>"
                                    "</td>", s->name_urlescaped, res->token);
        /* Restart program */
        if ((s->start && s->stop) || s->restart)
                StringBuffer_append(res->outputbuffer,
                                    "<td>"
                                    "<form method=POST action=%s>"
                                    "<input type=hidden name='securitytoken' value='%s'>"
                                    "<input type=hidden value='restart' name=action>"
                                    "<input type=submit value='Restart service'>"
                                    "</form>"
                                    "</td>", s->name_urlescaped, res->token);
        /* (un)monitor */
        StringBuffer_append(res->outputbuffer,
                                    "<td>"
                                    "<form method=POST action=%s>"
                                    "<input type=hidden name='securitytoken' value='%s'>"
                                    "<input type=hidden value='%s' name=action>"
                                    "<input type=submit value='%s'>"
                                    "</form>"
                                    "</td>",
                                    s->name_urlescaped,
                                    res->token,
                                    s->monitor ? "unmonitor" : "monitor",
                                    s->monitor ? "Disable monitoring" : "Enable monitoring");
        StringBuffer_append(res->outputbuffer, "</tr></table>");
}


static void print_service_rules_timeout(HttpResponse res, Service_T s) {
        for (ActionRate_T ar = s->actionratelist; ar; ar = ar->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "Timeout", "If restarted %d times within %d cycle(s) then %s", ar->count, ar->cycle, StringBuffer_toString(Util_printAction(ar->action->failed, sb)));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_nonexistence(HttpResponse res, Service_T s) {
        for (NonExist_T l = s->nonexistlist; l; l = l->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "Existence", "%s", StringBuffer_toString(Util_printRule(false, sb, l->action, "If doesn't exist")));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_existence(HttpResponse res, Service_T s) {
        for (Exist_T l = s->existlist; l; l = l->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "Non-Existence", "%s", StringBuffer_toString(Util_printRule(false, sb, l->action, "If exist")));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_port(HttpResponse res, Service_T s) {
        for (Port_T p = s->portlist; p; p = p->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                StringBuffer_T buf = StringBuffer_create(64);
                StringBuffer_append(buf, "If %s [%s]:%d%s",
                        p->check_invers ? "succeeded" : "failed", p->hostname, p->target.net.port, Util_portRequestDescription(p));
                if (p->outgoing.ip)
                        StringBuffer_append(buf, " via address %s", p->outgoing.ip);
                StringBuffer_append(buf, " type %s/%s protocol %s with timeout %s",
                        Util_portTypeDescription(p), Util_portIpDescription(p), p->protocol->name, Fmt_time2str(p->timeout, (char[11]){}));
                if (p->retry > 1)
                        StringBuffer_append(buf, " and retry %d times", p->retry);
                if (p->responsetime.limit > -1.)
                        StringBuffer_append(buf, " and responsetime %s %s", Operator_Names[p->responsetime.operator], Fmt_time2str(p->responsetime.limit, (char[11]){}));
#ifdef HAVE_OPENSSL
                if (p->target.net.ssl.options.flags) {
                        StringBuffer_append(buf, " using TLS");
                        const char *options = Ssl_printOptions(&p->target.net.ssl.options, (char[STRLEN]){}, STRLEN);
                        if (options && *options)
                                StringBuffer_append(buf, " with options {%s}", options);
                        if (p->target.net.ssl.certificate.minimumDays > 0)
                                StringBuffer_append(buf, " and certificate valid for at least %d days", p->target.net.ssl.certificate.minimumDays);
                        if (p->target.net.ssl.options.checksum)
                                StringBuffer_append(buf, " and certificate checksum %s equal to '%s'", Checksum_Names[p->target.net.ssl.options.checksumType], p->target.net.ssl.options.checksum);
                }
#endif
                _displayTableRow(res, true, "rule", "Port", "%s", StringBuffer_toString(Util_printRule(p->check_invers, sb, p->action, "%s", StringBuffer_toString(buf))));
                StringBuffer_free(&buf);
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_socket(HttpResponse res, Service_T s) {
        for (Port_T p = s->socketlist; p; p = p->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                StringBuffer_T buf = StringBuffer_create(64);
                StringBuffer_append(buf, "If %s %s type %s protocol %s with timeout %s", p->check_invers ? "succeeded" : "failed", p->target.unix.pathname, Util_portTypeDescription(p), p->protocol->name, Fmt_time2str(p->timeout, (char[11]){}));
                if (p->retry > 1)
                        StringBuffer_append(buf, " and retry %d times", p->retry);
                if (p->responsetime.limit > -1.)
                        StringBuffer_append(buf, " and responsetime %s %s", Operator_Names[p->responsetime.operator], Fmt_time2str(p->responsetime.limit, (char[11]){}));
                _displayTableRow(res, true, "rule", "Unix Socket", "%s", StringBuffer_toString(Util_printRule(p->check_invers, sb, p->action, "%s", StringBuffer_toString(buf))));
                StringBuffer_free(&buf);
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_icmp(HttpResponse res, Service_T s) {
        for (Icmp_T i = s->icmplist; i; i = i->next) {
                const char *key;
                StringBuffer_T sb = StringBuffer_create(256);
                StringBuffer_T buf = StringBuffer_create(64);
                switch (i->family) {
                        case Socket_Ip4:
                                key = "Ping4";
                                break;
                        case Socket_Ip6:
                                key = "Ping6";
                                break;
                        default:
                                key = "Ping";
                                break;
                }
                StringBuffer_append(buf, "If %s count %d size %d with timeout %s", i->check_invers ? "succeeded" : "failed", i->count, i->size, Fmt_time2str(i->timeout, (char[11]){}));
                if (i->outgoing.ip)
                        StringBuffer_append(buf, " via address %s", i->outgoing.ip);
                if (i->responsetime.limit > -1.)
                        StringBuffer_append(buf, " and responsetime %s %s", Operator_Names[i->responsetime.operator], Fmt_time2str(i->responsetime.limit, (char[11]){}));
                _displayTableRow(res, true, "rule", key, "%s", StringBuffer_toString(Util_printRule(i->check_invers, sb, i->action, "%s", StringBuffer_toString(buf))));
                StringBuffer_free(&buf);
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_perm(HttpResponse res, Service_T s) {
        if (s->perm) {
                StringBuffer_T sb = StringBuffer_create(256);
                if (s->perm->test_changes)
                        Util_printRule(false, sb, s->perm->action, "If changed");
                else
                        Util_printRule(false, sb, s->perm->action, "If failed %o", s->perm->perm);
                _displayTableRow(res, true, "rule", "Permissions", "%s", StringBuffer_toString(sb));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_uid(HttpResponse res, Service_T s) {
        if (s->uid) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "UID", "%s", StringBuffer_toString(Util_printRule(false, sb, s->uid->action, "If failed %d", s->uid->uid)));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_euid(HttpResponse res, Service_T s) {
        if (s->euid) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "EUID", "%s", StringBuffer_toString(Util_printRule(false, sb, s->euid->action, "If failed %d", s->euid->uid)));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_filedescriptors(HttpResponse res, Service_T s) {
        for (Filedescriptors_T o = s->filedescriptorslist; o; o = o->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                if (o->total) {
                        _displayTableRow(res, true, "rule", "Total filedescriptors", "%s", StringBuffer_toString(Util_printRule(false, sb, o->action, "If %s %lld", Operator_Names[o->operator], o->limit_absolute)));
                } else {
                        if (o->limit_absolute > -1LL)
                                _displayTableRow(res, true, "rule", "Filedescriptors", "%s", StringBuffer_toString(Util_printRule(false, sb, o->action, "If %s %lld", Operator_Names[o->operator], o->limit_absolute)));
                        else
                                _displayTableRow(res, true, "rule", "Filedescriptors", "%s", StringBuffer_toString(Util_printRule(false, sb, o->action, "If %s %.1f%%", Operator_Names[o->operator], o->limit_percent)));
                }
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_gid(HttpResponse res, Service_T s) {
        if (s->gid) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "GID", "%s", StringBuffer_toString(Util_printRule(false, sb, s->gid->action, "If failed %d", s->gid->gid)));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_secattr(HttpResponse res, Service_T s) {
        for (SecurityAttribute_T a = s->secattrlist; a; a = a->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "Security attribute", "%s", StringBuffer_toString(Util_printRule(false, sb, a->action, "If failed %s", a->attribute)));
                StringBuffer_free(&sb);
         }
}


static void print_service_rules_timestamp(HttpResponse res, Service_T s) {
        for (Timestamp_T t = s->timestamplist; t; t = t->next) {
                char key[STRLEN];
                snprintf(key, sizeof(key), "%c%s", toupper(Timestamp_Names[t->type][0]), Timestamp_Names[t->type] + 1);
                StringBuffer_T sb = StringBuffer_create(256);
                if (t->test_changes)
                        Util_printRule(false, sb, t->action, "If changed");
                else
                        Util_printRule(false, sb, t->action, "If %s %s", Operator_Names[t->operator], Fmt_time2str(t->time * 1000., (char[11]){}));
                _displayTableRow(res, true, "rule", key, "%s", StringBuffer_toString(sb));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_fsflags(HttpResponse res, Service_T s) {
        for (FsFlag_T l = s->fsflaglist; l; l = l->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "Filesystem flags", "%s", StringBuffer_toString(Util_printRule(false, sb, l->action, "If changed")));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_filesystem(HttpResponse res, Service_T s) {
        for (FileSystem_T dl = s->filesystemlist; dl; dl = dl->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                switch (dl->resource) {
                case Resource_Inode:
                        if (dl->limit_absolute > -1)
                                Util_printRule(false, sb, dl->action, "If %s %lld", Operator_Names[dl->operator], dl->limit_absolute);
                        else
                                Util_printRule(false, sb, dl->action, "If %s %.1f%%", Operator_Names[dl->operator], dl->limit_percent);
                        _displayTableRow(res, true, "rule", "Inodes usage limit", "%s", StringBuffer_toString(sb));
                        break;
                case Resource_InodeFree:
                        if (dl->limit_absolute > -1)
                                Util_printRule(false, sb, dl->action, "If %s %lld", Operator_Names[dl->operator], dl->limit_absolute);
                        else
                                Util_printRule(false, sb, dl->action, "If %s %.1f%%", Operator_Names[dl->operator], dl->limit_percent);
                        _displayTableRow(res, true, "rule", "Inodes free limit", "%s", StringBuffer_toString(sb));
                        break;
                case Resource_Space:
                        if (dl->limit_absolute > -1)
                                Util_printRule(false, sb, dl->action, "If %s %s", Operator_Names[dl->operator], Fmt_bytes2str(dl->limit_absolute, (char[10]){}));
                        else
                                Util_printRule(false, sb, dl->action, "If %s %.1f%%", Operator_Names[dl->operator], dl->limit_percent);
                        _displayTableRow(res, true, "rule", "Space usage limit", "%s", StringBuffer_toString(sb));
                        break;
                case Resource_SpaceFree:
                        if (dl->limit_absolute > -1)
                                Util_printRule(false, sb, dl->action, "If %s %s", Operator_Names[dl->operator], Fmt_bytes2str(dl->limit_absolute, (char[10]){}));
                        else
                                Util_printRule(false, sb, dl->action, "If %s %.1f%%", Operator_Names[dl->operator], dl->limit_percent);
                        _displayTableRow(res, true, "rule", "Space free limit", "%s", StringBuffer_toString(sb));
                        break;
                case Resource_ReadBytes:
                        _displayTableRow(res, true, "rule", "Read limit", "%s", StringBuffer_toString(Util_printRule(false, sb, dl->action, "If read %s %s/s", Operator_Names[dl->operator], Fmt_bytes2str(dl->limit_absolute, (char[10]){}))));
                        break;
                case Resource_ReadOperations:
                        _displayTableRow(res, true, "rule", "Read limit", "%s", StringBuffer_toString(Util_printRule(false, sb, dl->action, "If read %s %llu operations/s", Operator_Names[dl->operator], dl->limit_absolute)));
                        break;
                case Resource_WriteBytes:
                        _displayTableRow(res, true, "rule", "Write limit", "%s", StringBuffer_toString(Util_printRule(false, sb, dl->action, "If write %s %s/s", Operator_Names[dl->operator], Fmt_bytes2str(dl->limit_absolute, (char[10]){}))));
                        break;
                case Resource_WriteOperations:
                        _displayTableRow(res, true, "rule", "Write limit", "%s", StringBuffer_toString(Util_printRule(false, sb, dl->action, "If write %s %llu operations/s", Operator_Names[dl->operator], dl->limit_absolute)));
                        break;
                case Resource_ServiceTime:
                        _displayTableRow(res, true, "rule", "Service time limit", "%s", StringBuffer_toString(Util_printRule(false, sb, dl->action, "If service time %s %s/operation", Operator_Names[dl->operator], Fmt_time2str(dl->limit_absolute, (char[11]){}))));
                        break;
                default:
                        break;
                }
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_size(HttpResponse res, Service_T s) {
        for (Size_T sl = s->sizelist; sl; sl = sl->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                if (sl->test_changes)
                        Util_printRule(false, sb, sl->action, "If changed");
                else
                        Util_printRule(false, sb, sl->action, "If %s %llu byte(s)", Operator_Names[sl->operator], sl->size);
                _displayTableRow(res, true, "rule", "Size", "%s", StringBuffer_toString(sb));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_nlink(HttpResponse res, Service_T s) {
        for (NLink_T sl = s->nlinklist; sl; sl = sl->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                if (sl->test_changes)
                        Util_printRule(false, sb, sl->action, "If changed");
                else
                        Util_printRule(false, sb, sl->action, "If %s %llu", Operator_Names[sl->operator], sl->nlink);
                _displayTableRow(res, true, "rule", "Hardlink", "%s", StringBuffer_toString(sb));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_linkstatus(HttpResponse res, Service_T s) {
        for (LinkStatus_T l = s->linkstatuslist; l; l = l->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "Link status", "%s", StringBuffer_toString(Util_printRule(l->check_invers, sb, l->action, "If %s", l->check_invers ? "up" : "down")));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_linkspeed(HttpResponse res, Service_T s) {
        for (LinkSpeed_T l = s->linkspeedlist; l; l = l->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "Link capacity", "%s", StringBuffer_toString(Util_printRule(false, sb, l->action, "If changed")));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_linksaturation(HttpResponse res, Service_T s) {
        for (LinkSaturation_T l = s->linksaturationlist; l; l = l->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "Link saturation", "%s", StringBuffer_toString(Util_printRule(false, sb, l->action, "If %s %.1f%%", Operator_Names[l->operator], l->limit)));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_uploadbytes(HttpResponse res, Service_T s) {
        for (Bandwidth_T bl = s->uploadbyteslist; bl; bl = bl->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                if (bl->range == Time_Second)
                        _displayTableRow(res, true, "rule", "Upload bytes", "%s", StringBuffer_toString(Util_printRule(false, sb, bl->action, "If %s %s/s", Operator_Names[bl->operator], Fmt_bytes2str(bl->limit, (char[10]){}))));
                else
                        _displayTableRow(res, true, "rule", "Total upload bytes", "%s", StringBuffer_toString(Util_printRule(false, sb, bl->action, "If %s %s in last %d %s(s)", Operator_Names[bl->operator], Fmt_bytes2str(bl->limit, (char[10]){}), bl->rangecount, Util_timestr(bl->range))));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_uploadpackets(HttpResponse res, Service_T s) {
        for (Bandwidth_T bl = s->uploadpacketslist; bl; bl = bl->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                if (bl->range == Time_Second)
                        _displayTableRow(res, true, "rule", "Upload packets", "%s", StringBuffer_toString(Util_printRule(false, sb, bl->action, "If %s %lld packets/s", Operator_Names[bl->operator], bl->limit)));
                else
                        _displayTableRow(res, true, "rule", "Total upload packets", "%s", StringBuffer_toString(Util_printRule(false, sb, bl->action, "If %s %lld packets in last %d %s(s)", Operator_Names[bl->operator], bl->limit, bl->rangecount, Util_timestr(bl->range))));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_downloadbytes(HttpResponse res, Service_T s) {
        for (Bandwidth_T bl = s->downloadbyteslist; bl; bl = bl->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                if (bl->range == Time_Second)
                        _displayTableRow(res, true, "rule", "Download bytes", "%s", StringBuffer_toString(Util_printRule(false, sb, bl->action, "If %s %s/s", Operator_Names[bl->operator], Fmt_bytes2str(bl->limit, (char[10]){}))));
                else
                        _displayTableRow(res, true, "rule", "Total download bytes", "%s", StringBuffer_toString(Util_printRule(false, sb, bl->action, "If %s %s in last %d %s(s)", Operator_Names[bl->operator], Fmt_bytes2str(bl->limit, (char[10]){}), bl->rangecount, Util_timestr(bl->range))));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_downloadpackets(HttpResponse res, Service_T s) {
        for (Bandwidth_T bl = s->downloadpacketslist; bl; bl = bl->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                if (bl->range == Time_Second)
                        _displayTableRow(res, true, "rule", "Download packets", "%s", StringBuffer_toString(Util_printRule(false, sb, bl->action, "If %s %lld packets/s", Operator_Names[bl->operator], bl->limit)));
                else
                        _displayTableRow(res, true, "rule", "Total download packets", "%s", StringBuffer_toString(Util_printRule(false, sb, bl->action, "If %s %lld packets in last %d %s(s)", Operator_Names[bl->operator], bl->limit, bl->rangecount, Util_timestr(bl->range))));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_uptime(HttpResponse res, Service_T s) {
        for (Uptime_T ul = s->uptimelist; ul; ul = ul->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "Uptime", "%s", StringBuffer_toString(Util_printRule(false, sb, ul->action, "If %s %s", Operator_Names[ul->operator], _getUptime(ul->uptime, (char[256]){}))));
                StringBuffer_free(&sb);
        }
}

static void print_service_rules_content(HttpResponse res, Service_T s) {
        if (s->type != Service_Process) {
                for (Match_T ml = s->matchignorelist; ml; ml = ml->next) {
                        StringBuffer_T sb = StringBuffer_create(256);
                        _displayTableRow(res, true, "rule", "Ignore content", "%s", StringBuffer_toString(Util_printRule(false, sb, ml->action, "If content %s \"%s\"", ml->not ? "!=" : "=", ml->match_string)));
                        StringBuffer_free(&sb);
                }
                for (Match_T ml = s->matchlist; ml; ml = ml->next) {
                        StringBuffer_T sb = StringBuffer_create(256);
                        _displayTableRow(res, true, "rule", "Content match", "%s", StringBuffer_toString(Util_printRule(false, sb, ml->action, "If content %s \"%s\"", ml->not ? "!=" : "=", ml->match_string)));
                        StringBuffer_free(&sb);
                }
        }
}


static void print_service_rules_checksum(HttpResponse res, Service_T s) {
        if (s->checksum) {
                StringBuffer_T sb = StringBuffer_create(256);
                if (s->checksum->test_changes)
                        Util_printRule(false, sb, s->checksum->action, "If changed %s", Checksum_Names[s->checksum->type]);
                else
                        Util_printRule(false, sb, s->checksum->action, "If failed %s(%s)", s->checksum->hash, Checksum_Names[s->checksum->type]);
                _displayTableRow(res, true, "rule", "Checksum", "%s", StringBuffer_toString(sb));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_pid(HttpResponse res, Service_T s) {
        for (Pid_T l = s->pidlist; l; l = l->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "PID", "%s", StringBuffer_toString(Util_printRule(false, sb, l->action, "If changed")));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_ppid(HttpResponse res, Service_T s) {
        for (Pid_T l = s->ppidlist; l; l = l->next) {
                StringBuffer_T sb = StringBuffer_create(256);
                _displayTableRow(res, true, "rule", "PPID", "%s", StringBuffer_toString(Util_printRule(false, sb, l->action, "If changed")));
                StringBuffer_free(&sb);
        }
}


static void print_service_rules_program(HttpResponse res, Service_T s) {
        if (s->type == Service_Program) {
                _displayTableRow(res, false, "rule", "Program timeout", "Terminate the program if not finished within %s", Fmt_time2str(s->program->timeout, (char[11]){}));
                for (Status_T status = s->statuslist; status; status = status->next) {
                        StringBuffer_T sb = StringBuffer_create(256);
                        if (status->operator == Operator_Changed)
                                Util_printRule(false, sb, status->action, "If exit value changed");
                        else
                                Util_printRule(false, sb, status->action, "If exit value %s %d", OperatorShort_Names[status->operator], status->return_value);
                        _displayTableRow(res, true, "rule", "Test Exit value", "%s", StringBuffer_toString(sb));
                        StringBuffer_free(&sb);
                }
        }
}


static void print_service_rules_resource(HttpResponse res, Service_T s) {
        char buf[STRLEN];
        for (Resource_T q = s->resourcelist; q; q = q->next) {
                const char *key = NULL;
                StringBuffer_T sb = StringBuffer_create(256);
                switch (q->resource_id) {
                        case Resource_CpuPercent:
                                key = "CPU usage limit";
                                break;

                        case Resource_CpuPercentTotal:
                                key = "CPU usage limit (incl. children)";
                                break;

                        case Resource_CpuUser:
                                key = "CPU user limit";
                                break;

                        case Resource_CpuSystem:
                                key = "CPU system limit";
                                break;

                        case Resource_CpuWait:
                                key = "CPU I/O wait limit";
                                break;

                        case Resource_CpuNice:
                                key = "CPU nice limit";
                                break;

                        case Resource_CpuHardIRQ:
                                key = "CPU hardware IRQ limit";
                                break;

                        case Resource_CpuSoftIRQ:
                                key = "CPU software IRQ limit";
                                break;

                        case Resource_CpuSteal:
                                key = "CPU steal limit";
                                break;

                        case Resource_CpuGuest:
                                key = "CPU guest limit";
                                break;

                        case Resource_CpuGuestNice:
                                key = "CPU guest nice limit";
                                break;

                        case Resource_MemoryPercent:
                                key = "Memory usage limit";
                                break;

                        case Resource_MemoryKbyte:
                                key = "Memory amount limit";
                                break;

                        case Resource_SwapPercent:
                                key = "Swap usage limit";
                                break;

                        case Resource_SwapKbyte:
                                key = "Swap amount limit";
                                break;

                        case Resource_LoadAverage1m:
                                key = "Load average (1m)";
                                break;

                        case Resource_LoadAverage5m:
                                key = "Load average (5m)";
                                break;

                        case Resource_LoadAverage15m:
                                key = "Load average (15m)";
                                break;

                        case Resource_LoadAveragePerCore1m:
                                key = "Load average per core (1m)";
                                break;

                        case Resource_LoadAveragePerCore5m:
                                key = "Load average per core (5m)";
                                break;

                        case Resource_LoadAveragePerCore15m:
                                key = "Load average per core (15m)";
                                break;

                        case Resource_Threads:
                                key = "Threads";
                                break;

                        case Resource_Children:
                                key = "Children";
                                break;

                        case Resource_MemoryKbyteTotal:
                                key = "Memory amount limit (incl. children)";
                                break;

                        case Resource_MemoryPercentTotal:
                                key = "Memory usage limit (incl. children)";
                                break;

                        case Resource_ReadBytes:
                                key = "Disk read limit";
                                break;

                        case Resource_ReadOperations:
                                key = "Disk read limit";
                                break;

                        case Resource_WriteBytes:
                                key = "Disk write limit";
                                break;

                        case Resource_WriteOperations:
                                key = "Disk write limit";
                                break;

                        default:
                                break;
                }
                switch (q->resource_id) {
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
                                Util_printRule(false, sb, q->action, "If %s %.1f%%", Operator_Names[q->operator], q->limit);
                                break;

                        case Resource_MemoryKbyte:
                        case Resource_SwapKbyte:
                        case Resource_MemoryKbyteTotal:
                                Util_printRule(false, sb, q->action, "If %s %s", Operator_Names[q->operator], Fmt_bytes2str(q->limit, buf));
                                break;

                        case Resource_LoadAverage1m:
                        case Resource_LoadAverage5m:
                        case Resource_LoadAverage15m:
                        case Resource_LoadAveragePerCore1m:
                        case Resource_LoadAveragePerCore5m:
                        case Resource_LoadAveragePerCore15m:
                                Util_printRule(false, sb, q->action, "If %s %.1f", Operator_Names[q->operator], q->limit);
                                break;

                        case Resource_Threads:
                        case Resource_Children:
                                Util_printRule(false, sb, q->action, "If %s %.0f", Operator_Names[q->operator], q->limit);
                                break;

                        case Resource_ReadBytes:
                        case Resource_ReadBytesPhysical:
                        case Resource_WriteBytes:
                        case Resource_WriteBytesPhysical:
                                Util_printRule(false, sb, q->action, "if %s %s", Operator_Names[q->operator], Fmt_bytes2str(q->limit, (char[10]){}));
                                break;

                        case Resource_ReadOperations:
                        case Resource_WriteOperations:
                                Util_printRule(false, sb, q->action, "if %s %.0f operations/s", Operator_Names[q->operator], q->limit);
                                break;

                        default:
                                break;
                }
                if (key)
                        _displayTableRow(res, true, "rule", key, "%s", StringBuffer_toString(sb));
                StringBuffer_free(&sb);
        }
}


static bool is_readonly(HttpRequest req) {
        Socket_Family sfam = Socket_getFamily(req->S);
        if ((Run.httpd.socket.net.readonly  && (sfam != Socket_Unix)) ||
            (Run.httpd.socket.unix.readonly && (sfam == Socket_Unix))
           ) {
                return true;
        }
        if (req->remote_user) {
                Auth_T user_creds = Util_getUserCredentials(req->remote_user);
                return (user_creds ? user_creds->is_readonly : true);
        }
        return false;
}


/* ----------------------------------------------------------- Status output */


/* Print status in the given format. Text status is default. */
static void print_status(HttpRequest req, HttpResponse res, int version) {
        const char *stringFormat = get_parameter(req, "format");
        if (stringFormat && Str_startsWith(stringFormat, "xml")) {
                char buf[STRLEN];
                StringBuffer_T sb = StringBuffer_create(256);
                status_xml(sb, NULL, version, Socket_getLocalHost(req->S, buf, sizeof(buf)), NULL);
                StringBuffer_append(res->outputbuffer, "%s", StringBuffer_toString(sb));
                StringBuffer_free(&sb);
                set_content_type(res, "text/xml");
        } else {
                set_content_type(res, "text/plain");

                StringBuffer_append(res->outputbuffer, "Monit %s uptime: %s\n\n", VERSION, _getUptime(ProcessTree_getProcessUptime(getpid()), (char[256]){}));

                struct ServiceMap_T ap = {.found = 0, .data.status.res = res};
                const char *stringGroup = Util_urlDecode((char *)get_parameter(req, "group"));
                const char *stringService = Util_urlDecode((char *)get_parameter(req, "service"));
                if (stringGroup) {
                        for (ServiceGroup_T sg = Service_Group_List; sg; sg = sg->next) {
                                if (IS(stringGroup, sg->name)) {
                                        for (_list_t m = sg->members->head; m; m = m->next) {
                                                status_service_txt(m->e, res);
                                                ap.found++;
                                        }
                                        break;
                                }
                        }
                } else {
                        _serviceMapByName(stringService, _serviceMapStatus, &ap);
                }
                if (ap.found == 0) {
                        if (stringGroup)
                                send_error(req, res, SC_BAD_REQUEST, "Service group '%s' not found", stringGroup);
                        else if (stringService)
                                send_error(req, res, SC_BAD_REQUEST, "Service '%s' not found", stringService);
                        else
                                send_error(req, res, SC_BAD_REQUEST, "No service found");
                }
        }
}


static void print_summary(HttpRequest req, HttpResponse res) {
        set_content_type(res, "text/plain");

        StringBuffer_append(res->outputbuffer, "Monit %s uptime: %s\n", VERSION, _getUptime(ProcessTree_getProcessUptime(getpid()), (char[256]){}));

        struct ServiceMap_T ap = {.found = 0};
        const char *stringGroup = Util_urlDecode((char *)get_parameter(req, "group"));
        const char *stringService = Util_urlDecode((char *)get_parameter(req, "service"));

        ap.data.summary.box = TextBox_new(res->outputbuffer, 3, (TextBoxColumn_T []){
                        {.name = "Service Name", .width = 31, .wrap = false, .align = TextBoxAlign_Left},
                        {.name = "Status",       .width = 26, .wrap = false, .align = TextBoxAlign_Left},
                        {.name = "Type",         .width = 13, .wrap = false, .align = TextBoxAlign_Left}
                  }, true);

        if (stringGroup) {
                for (ServiceGroup_T sg = Service_Group_List; sg; sg = sg->next) {
                        if (IS(stringGroup, sg->name)) {
                                for (_list_t m = sg->members->head; m; m = m->next) {
                                        _printServiceSummary(ap.data.summary.box, m->e);
                                        ap.found++;
                                }
                                break;
                        }
                }
        } else if (stringService) {
                _serviceMapByName(stringService, _serviceMapSummary, &ap);
        } else {
                _serviceMapByType(Service_System, _serviceMapSummary, &ap);
                _serviceMapByType(Service_Process, _serviceMapSummary, &ap);
                _serviceMapByType(Service_File, _serviceMapSummary, &ap);
                _serviceMapByType(Service_Fifo, _serviceMapSummary, &ap);
                _serviceMapByType(Service_Directory, _serviceMapSummary, &ap);
                _serviceMapByType(Service_Filesystem, _serviceMapSummary, &ap);
                _serviceMapByType(Service_Host, _serviceMapSummary, &ap);
                _serviceMapByType(Service_Net, _serviceMapSummary, &ap);
                _serviceMapByType(Service_Program, _serviceMapSummary, &ap);
        }

        TextBox_free(&ap.data.summary.box);

        if (ap.found == 0) {
                if (stringGroup)
                        send_error(req, res, SC_BAD_REQUEST, "Service group '%s' not found", stringGroup);
                else if (stringService)
                        send_error(req, res, SC_BAD_REQUEST, "Service '%s' not found", stringService);
                else
                        send_error(req, res, SC_BAD_REQUEST, "No service found");
        }
}


static void _updateReportStatistics(Service_T s, ReportStatics_T statistics) {
        if (s->monitor == Monitor_Not)
                statistics->unmonitored++;
        else if (s->monitor & Monitor_Init)
                statistics->init++;
        else if (s->error)
                statistics->down++;
        else
                statistics->up++;
        statistics->total++;
}


static void _printReport(HttpRequest req, HttpResponse res) {
        set_content_type(res, "text/plain");
        const char *type = get_parameter(req, "type");
        const char *group = Util_urlDecode((char *)get_parameter(req, "group"));
        struct ReportStatics_T reportStatics = {};
        if (group) {
                for (ServiceGroup_T sg = Service_Group_List; sg; sg = sg->next) {
                        if (IS(group, sg->name)) {
                                for (_list_t m = sg->members->head; m; m = m->next) {
                                        _updateReportStatistics(m->e, &reportStatics);
                                }
                        }
                }
        } else {
                for (Service_T s = Service_List; s; s = s->next) {
                        _updateReportStatistics(s, &reportStatics);
                }
        }
        if (! type) {
                StringBuffer_append(res->outputbuffer,
                        "up:           %*.0f (%.1f%%)\n"
                        "down:         %*.0f (%.1f%%)\n"
                        "initialising: %*.0f (%.1f%%)\n"
                        "unmonitored:  %*.0f (%.1f%%)\n"
                        "total:        %*.0f services\n",
                        3, reportStatics.up, 100. * reportStatics.up / reportStatics.total,
                        3, reportStatics.down, 100. * reportStatics.down / reportStatics.total,
                        3, reportStatics.init, 100. * reportStatics.init / reportStatics.total,
                        3, reportStatics.unmonitored, 100. * reportStatics.unmonitored / reportStatics.total,
                        3, reportStatics.total);
        } else if (Str_isEqual(type, "up")) {
                StringBuffer_append(res->outputbuffer, "%.0f\n", reportStatics.up);
        } else if (Str_isEqual(type, "down")) {
                StringBuffer_append(res->outputbuffer, "%.0f\n", reportStatics.down);
        } else if (Str_startsWith(type, "initiali")) { // allow 'initiali(s|z)ing'
                StringBuffer_append(res->outputbuffer, "%.0f\n", reportStatics.init);
        } else if (Str_isEqual(type, "unmonitored")) {
                StringBuffer_append(res->outputbuffer, "%.0f\n", reportStatics.unmonitored);
        } else if (Str_isEqual(type, "total")) {
                StringBuffer_append(res->outputbuffer, "%.0f\n", reportStatics.total);
        } else {
                send_error(req, res, SC_BAD_REQUEST, "Invalid report type: '%s'", type);
        }
}


static void status_service_txt(Service_T s, HttpResponse res) {
        char buf[STRLEN];
        StringBuffer_append(res->outputbuffer,
                COLOR_BOLDCYAN "%s '%s'" COLOR_RESET "\n"
                "  %-28s %s\n",
                Servicetype_Names[s->type], s->name,
                "status", get_service_status(TXT, s, buf, sizeof(buf)));
        StringBuffer_append(res->outputbuffer,
                "  %-28s %s\n",
                "monitoring status", get_monitoring_status(TXT, s, buf, sizeof(buf)));
        StringBuffer_append(res->outputbuffer,
                "  %-28s %s\n",
                "monitoring mode", Mode_Names[s->mode]);
        StringBuffer_append(res->outputbuffer,
                "  %-28s %s\n",
                "on reboot", onReboot_Names[s->onreboot]);
        _printStatus(TXT, res, s);
        StringBuffer_append(res->outputbuffer, "\n");
}


static char *get_monitoring_status(Output_Type type, Service_T s, char *buf, int buflen) {
        assert(s);
        assert(buf);
        if (s->monitor == Monitor_Not) {
                if (type == HTML)
                        snprintf(buf, buflen, "<span class='gray-text'>Not monitored</span>");
                else
                        snprintf(buf, buflen, TextColor_lightYellow("Not monitored"));
        } else if (s->monitor & Monitor_Waiting) {
                if (type == HTML)
                        snprintf(buf, buflen, "<span>Waiting</span>");
                else
                        snprintf(buf, buflen, TextColor_white("Waiting"));
        } else if (s->monitor & Monitor_Init) {
                if (type == HTML)
                        snprintf(buf, buflen, "<span class='blue-text'>Initializing</span>");
                else
                        snprintf(buf, buflen, TextColor_lightBlue("Initializing"));
        } else if (s->monitor & Monitor_Yes) {
                if (type == HTML)
                        snprintf(buf, buflen, "<span>Monitored</span>");
                else
                        snprintf(buf, buflen, "Monitored");
        }
        return buf;
}


static char *get_service_status(Output_Type type, Service_T s, char *buf, int buflen) {
        assert(s);
        assert(buf);
        if (s->monitor == Monitor_Not || s->monitor & Monitor_Init) {
                get_monitoring_status(type, s, buf, buflen);
        } else if (s->error == 0) {
                snprintf(buf, buflen, type == HTML ? "<span class='green-text'>OK</span>" : TextColor_lightGreen("OK"));
        } else {
                // In the case that the service has actually some failure, the error bitmap will be non zero
                char *p = buf;
                EventTable_T *et = Event_Table;
                while ((*et).id) {
                        if (s->error & (*et).id) {
                                bool inverse = false;
                                if ((*et).id == Event_Link && s->inverseStatus)
                                        inverse = true;
                                if (p > buf)
                                        p += snprintf(p, buflen - (p - buf), " | ");
                                if (s->error_hint & (*et).id) {
                                        if (type == HTML)
                                                p += snprintf(p, buflen - (p - buf), "<span class='orange-text'>%s</span>", (*et).description_changed);
                                        else
                                                p += snprintf(p, buflen - (p - buf), TextColor_lightYellow("%s", (*et).description_changed));
                                } else {
                                        if (type == HTML)
                                                p += snprintf(p, buflen - (p - buf), "<span class='red-text'>%s</span>", inverse ? (*et).description_succeeded : (*et).description_failed);
                                        else
                                                p += snprintf(p, buflen - (p - buf), TextColor_lightRed("%s", inverse ? (*et).description_succeeded : (*et).description_failed));
                                }
                        }
                        et++;
                }
        }
        if (s->doaction)
                snprintf(buf + strlen(buf), buflen - strlen(buf) - 1, " - %s pending", Action_Names[s->doaction]);
        return buf;
}

