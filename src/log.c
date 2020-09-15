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

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
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

#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include "monit.h"

// libmonit
#include "system/Time.h"


/**
 *  Implementation of a logger that appends log messages to a file
 *  with a preceding timestamp. Methods support both syslog or own
 *  logfile.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


static FILE *_LOG = NULL;
static Mutex_T _mutex = PTHREAD_MUTEX_INITIALIZER;


static struct mylogpriority {
        int  priority;
        const char *description;
} logPriority[] = {
        {LOG_EMERG,   "emergency"},
        {LOG_ALERT,   "alert"},
        {LOG_CRIT,    "critical"},
        {LOG_ERR,     "error"},
        {LOG_WARNING, "warning"},
        {LOG_NOTICE,  "notice"},
        {LOG_INFO,    "info"},
        {LOG_DEBUG,   "debug"},
        {-1,          NULL}
};


/* ----------------------------------------------------------------- Private */


/**
 * Open a log file or syslog
 */
static bool _open(void) {
        if (Run.flags & Run_UseSyslog) {
                openlog(prog, LOG_PID, Run.facility);
        } else {
                _LOG = fopen(Run.files.log, "a");
                if (! _LOG) {
                        Log_error("Error opening the log file '%s' for writing -- %s\n", Run.files.log, STRERROR);
                        return false;
                }
                /* Set logger in unbuffered mode */
                setvbuf(_LOG, NULL, _IONBF, 0);
        }
        return true;
}


/**
 * Get a textual description of the actual log priority.
 * @param p The log priority
 * @return A string describing the log priority in clear text. If the
 * priority is not found NULL is returned.
 */
static const char *_priorityDescription(int p) {
        struct mylogpriority *lp = logPriority;
        while ((*lp).description) {
                if (p == (*lp).priority) {
                        return (*lp).description;
                }
                lp++;
        }
        return "unknown";
}


/**
 * Log a message to monits logfile or syslog.
 * @param priority A message priority
 * @param s A formatted (printf-style) string to log
 */
__attribute__((format (printf, 2, 0)))
static void _log(int priority, const char *s, va_list ap) {
        ASSERT(s);
        va_list ap_copy;
        LOCK(_mutex)
        {

                FILE *output = priority < LOG_INFO ? stderr : stdout;
                va_copy(ap_copy, ap);
                vfprintf(output, s, ap_copy);
                va_end(ap_copy);
                fflush(output);
                if (Run.flags & Run_Log) {
                        if (Run.flags & Run_UseSyslog) {
                                va_copy(ap_copy, ap);
                                vsyslog(priority, s, ap_copy);
                                va_end(ap_copy);
                        } else if (_LOG) {
                                fprintf(_LOG, "[%s] %-8s : ", Time_fmt((char[STRLEN]){}, STRLEN, TIMEFORMAT, Time_now()), _priorityDescription(priority));
                                va_copy(ap_copy, ap);
                                vfprintf(_LOG, s, ap_copy);
                                va_end(ap_copy);
                        }
                }
        }
        END_LOCK;
}


static void _backtrace(void) {
#ifdef HAVE_BACKTRACE
        int i, frames;
        void *callstack[128];
        char **strs;

        if (Run.debug >= 2) {
                frames = backtrace(callstack, 128);
                strs = backtrace_symbols(callstack, frames);
                Log_debug("-------------------------------------------------------------------------------\n");
                for (i = 0; i < frames; ++i)
                Log_debug("    %s\n", strs[i]);
                Log_debug("-------------------------------------------------------------------------------\n");
                FREE(strs);
        }
#endif
}


/* ------------------------------------------------------------------------- */


#ifndef HAVE_VSYSLOG
#ifdef HAVE_SYSLOG
void vsyslog(int facility_priority, const char *format, va_list arglist) {
        char msg[STRLEN+1];
        vsnprintf(msg, STRLEN, format, arglist);
        syslog(facility_priority, "%s", msg);
}
#endif /* HAVE_SYSLOG */
#endif /* HAVE_VSYSLOG */


/* ------------------------------------------------------------------ Public */


/**
 * Initialize the log system and 'log' function
 * @return true if the log system was successfully initialized
 */
bool Log_init() {
        if (! (Run.flags & Run_Log))
                return true;
        if (! _open())
                return false;
        /* Register Log_close to be called at program termination */
        atexit(Log_close);
        return true;
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 */
void Log_emergency(const char *s, ...) {
        ASSERT(s);
        va_list ap;
        va_start(ap, s);
        _log(LOG_EMERG, s, ap);
        va_end(ap);
        _backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 * @param ap A variable argument list
 */
void Log_vemergency(const char *s, va_list ap) {
        ASSERT(s);
        va_list ap_copy;
        va_copy(ap_copy, ap);
        _log(LOG_EMERG, s, ap);
        va_end(ap_copy);
        _backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 */
void Log_alert(const char *s, ...) {
        ASSERT(s);
        va_list ap;
        va_start(ap, s);
        _log(LOG_ALERT, s, ap);
        va_end(ap);
        _backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 * @param ap A variable argument list
 */
void Log_valert(const char *s, va_list ap) {
        ASSERT(s);
        va_list ap_copy;
        va_copy(ap_copy, ap);
        _log(LOG_ALERT, s, ap);
        va_end(ap_copy);
        _backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 */
void Log_critical(const char *s, ...) {
        ASSERT(s);
        va_list ap;
        va_start(ap, s);
        _log(LOG_CRIT, s, ap);
        va_end(ap);
        _backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 * @param ap A variable argument list
 */
void Log_vcritical(const char *s, va_list ap) {
        ASSERT(s);
        va_list ap_copy;
        va_copy(ap_copy, ap);
        _log(LOG_CRIT, s, ap);
        va_end(ap_copy);
        _backtrace();
}


/*
 * Called by libmonit on Exception. Log
 * error and abort the application
 */
void Log_abort_handler(const char *s, va_list ap) {
        ASSERT(s);
        va_list ap_copy;
        va_copy(ap_copy, ap);
        _log(LOG_CRIT, s, ap);
        va_end(ap_copy);
        if (Run.debug)
                abort();
        exit(1);
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 */
void Log_error(const char *s, ...) {
        ASSERT(s);
        va_list ap;
        va_start(ap, s);
        _log(LOG_ERR, s, ap);
        va_end(ap);
        _backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 * @param ap A variable argument list
 */
void Log_verror(const char *s, va_list ap) {
        ASSERT(s);
        va_list ap_copy;
        va_copy(ap_copy, ap);
        _log(LOG_ERR, s, ap);
        va_end(ap_copy);
        _backtrace();
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 */
void Log_warning(const char *s, ...) {
        ASSERT(s);
        va_list ap;
        va_start(ap, s);
        _log(LOG_WARNING, s, ap);
        va_end(ap);
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 * @param ap A variable argument list
 */
void Log_vwarning(const char *s, va_list ap) {
        ASSERT(s);
        va_list ap_copy;
        va_copy(ap_copy, ap);
        _log(LOG_WARNING, s, ap);
        va_end(ap_copy);
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 */
void Log_notice(const char *s, ...) {
        ASSERT(s);
        va_list ap;
        va_start(ap, s);
        _log(LOG_NOTICE, s, ap);
        va_end(ap);
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 * @param ap A variable argument list
 */
void Log_vnotice(const char *s, va_list ap) {
        ASSERT(s);
        va_list ap_copy;
        va_copy(ap_copy, ap);
        _log(LOG_NOTICE, s, ap);
        va_end(ap_copy);
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 */
void Log_info(const char *s, ...) {
        ASSERT(s);
        va_list ap;
        va_start(ap, s);
        _log(LOG_INFO, s, ap);
        va_end(ap);
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 * @param ap A variable argument list
 */
void Log_vinfo(const char *s, va_list ap) {
        ASSERT(s);
        va_list ap_copy;
        va_copy(ap_copy, ap);
        _log(LOG_INFO, s, ap);
        va_end(ap_copy);
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 */
void Log_debug(const char *s, ...) {
        ASSERT(s);
        if (Run.debug) {
                va_list ap;
                va_start(ap, s);
                _log(LOG_DEBUG, s, ap);
                va_end(ap);
        }
}


/**
 * Logging interface with priority support
 * @param s A formatted (printf-style) string to log
 * @param ap A variable argument list
 */
void Log_vdebug(const char *s, va_list ap) {
        ASSERT(s);
        if (Run.debug) {
                va_list ap_copy;
                va_copy(ap_copy, ap);
                _log(LOG_NOTICE, s, ap);
                va_end(ap_copy);
        }
}


/**
 * Close the log file or syslog
 */
void Log_close() {
        if (Run.flags & Run_UseSyslog) {
                closelog();
        }
        if (_LOG  && (0 != fclose(_LOG))) {
                Log_error("Error closing the log file -- %s\n", STRERROR);
        }
        _LOG = NULL;
}
