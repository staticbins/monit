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
#include <locale.h>

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include "monit.h"
#include "SystemInfo.h"
#include "Proc.h"
#include "ProcessTable.h"
#include "state.h"
#include "event.h"
#include "engine.h"
#include "client.h"
#include "MMonit.h"
#include "md5.h"
#include "sha1.h"
#include "checksum.h"

// libmonit
#include "Bootstrap.h"
#include "io/Dir.h"
#include "io/File.h"
#include "system/Time.h"
#include "util/List.h"
#include "exceptions/AssertException.h"


/**
 *  DESCRIPTION
 *    monit - system for monitoring services on a Unix system
 *
 *  SYNOPSIS
 *    monit [options] {arguments}
 *
 *  @file
 */


/* -------------------------------------------------------------- Prototypes */


static void  do_init(void);                   /* Initialize this application */
static void  do_reinit(bool full);  /* Re-initialize the runtime application */
static void  do_action(List_T);          /* Dispatch to the submitted action */
static void  do_exit(bool);                           /* Finalize monit */
static void  do_default(void);                          /* Do default action */
static void  handle_options(int, char **, List_T); /* Handle program options */
static void  help(void);             /* Print program help message to stdout */
static void  version(void);                     /* Print version information */
static void *heartbeat(void *args);              /* M/Monit heartbeat thread */
static void do_reload(int);             /* Signalhandler for a daemon reload */
static void do_destroy(int);         /* Signalhandler for monit finalization */
static void do_wakeup(int);        /* Signalhandler for a daemon wakeup call */
static void waitforchildren(void); /* Wait for any child process not running */



/* ------------------------------------------------------------------ Global */


const char *Prog;                                /**< The Name of this Program */
struct Run_T Run;                        /**< Struct holding runtime constants */
Service_T Service_List;                 /**< The service list (created in p.y) */
Service_T Service_List_Conf;    /**< The service list in conf file (c. in p.y) */
ServiceGroup_T Service_Group_List;/**< The service group list (created in p.y) */
SystemInfo_T System_Info;                              /**< System information */
ProcessTable_T Process_Table;                        /**< Shared Process Table */

Thread_T Heartbeat_Thread;
Sem_T    Heartbeat_Cond;
Mutex_T  Heartbeat_Mutex;
static volatile bool isHeartbeatRunning = false;

const char *Action_Names[] = {"ignore", "alert", "restart", "stop", "exec", "unmonitor", "start", "monitor", ""};
const char *Mode_Names[] = {"active", "passive"};
const char *onReboot_Names[] = {"start", "nostart", "laststate"};
const char *Checksum_Names[] = {"UNKNOWN", "MD5", "SHA1"};
const char *Operator_Names[] = {"less than", "less than or equal to", "greater than", "greater than or equal to", "equal to", "not equal to", "changed"};
const char *OperatorShort_Names[] = {"<", "<=", ">", ">=", "=", "!=", "<>"};
const char *Servicetype_Names[] = {"Filesystem", "Directory", "File", "Process", "Remote Host", "System", "Fifo", "Program", "Network"};
const char *Path_Names[] = {"Path", "Path", "Path", "Pid file", "Path", "", "Path"};
const char *Icmp_Names[] = {"Reply", "", "", "Destination Unreachable", "Source Quench", "Redirect", "", "", "Ping", "", "", "Time Exceeded", "Parameter Problem", "Timestamp Request", "Timestamp Reply", "Information Request", "Information Reply", "Address Mask Request", "Address Mask Reply"};
const char *Socket_Names[] = {"unix", "IP", "IPv4", "IPv6"};
const char *Timestamp_Names[] = {"modify/change time", "access time", "change time", "modify time"};
const char *Httpmethod_Names[] = {"", "HEAD", "GET"};


/* ------------------------------------------------------------------ Public */


/**
 * The Prime mover
 */
int main(int argc, char **argv) {
        Bootstrap(); // Bootstrap libmonit
        Bootstrap_setAbortHandler(Log_abort_handler);  // Abort Monit on exceptions thrown by libmonit
        Bootstrap_setErrorHandler(Log_verror);
        setlocale(LC_ALL, "C");
        Prog = File_basename(argv[0]);
#ifdef HAVE_OPENSSL
        Ssl_start();
#endif
        init_env();
        List_T arguments = List_new();
        TRY
        {
                handle_options(argc, argv, arguments);
        }
        ELSE
        {
                Log_error("%s\n", Exception_frame.message);
                exit(1);
        }
        END_TRY;
        do_init();
        do_action(arguments);
        List_free(&arguments);
        do_exit(false);
}


/**
 * Wakeup a sleeping monit daemon.
 * Returns true on success otherwise false
 */
bool do_wakeupcall(void) {
        pid_t pid;

        if ((pid = exist_daemon()) > 0) {
                kill(pid, SIGUSR1);
                Log_info("Monit daemon with PID %d awakened\n", pid);

                return true;
        }

        return false;
}


bool interrupt(void) {
        return Run.flags & Run_Stopped || Run.flags & Run_DoReload;
}


/* ----------------------------------------------------------------- Private */


static void _validateOnce(void) {
        if (State_open()) {
                State_restore();
                validate();
                State_save();
                State_close();
        }
}


/**
 * Initialize this application - Register signal handlers,
 * Parse the control file and initialize the program's
 * datastructures and the log system.
 */
static void do_init(void) {
        /*
         * Register interest for the SIGTERM signal,
         * in case we run in daemon mode this signal
         * will terminate a running daemon.
         */
        signal(SIGTERM, do_destroy);

        /*
         * Register interest for the SIGUSER1 signal,
         * in case we run in daemon mode this signal
         * will wakeup a sleeping daemon.
         */
        signal(SIGUSR1, do_wakeup);

        /*
         * Register interest for the SIGINT signal,
         * in case we run as a server but not as a daemon
         * we need to catch this signal if the user pressed
         * CTRL^C in the terminal
         */
        signal(SIGINT, do_destroy);

        /*
         * Register interest for the SIGHUP signal,
         * in case we run in daemon mode this signal
         * will reload the configuration.
         */
        signal(SIGHUP, do_reload);

        /*
         * Register no interest for the SIGPIPE signal,
         */
        signal(SIGPIPE, SIG_IGN);

        /*
         * Initialize the random number generator
         */
        srandom((unsigned)(Time_now() + getpid()));

        /*
         * Initialize the Runtime mutex. This mutex
         * is used to synchronize handling of global
         * service data
         */
        Mutex_init(Run.mutex);

        /*
         * Initialize heartbeat mutex and condition
         */
        Mutex_init(Heartbeat_Mutex);
        Sem_init(Heartbeat_Cond);

        /*
         * Get the position of the control file
         */
        if (! Run.files.control)
                Run.files.control = file_findControlFile();

        /*
         * Initialize the system information data collecting interface
         */
        if (SystemInfo_init()) {
                Run.flags |= Run_ProcessEngineEnabled;
        }

        /*
         * Start the Parser and create the service list. This will also set
         * any Runtime constants defined in the controlfile.
         */
        if (! parse(Run.files.control))
                exit(1);

        /*
         * Initialize the log system
         */
        if (! Log_init())
                exit(1);

        /*
         * Did we find any service ?
         */
        if (! Service_List) {
                Log_error("No service has been specified\n");
                exit(0);
        }

        /*
         * Initialize Runtime file variables
         */
        file_init();

        /*
         * Should we print debug information ?
         */
        if (Run.debug) {
                Util_printRunList();
                Util_printServiceList();
        }
        
        /*
         * Reap any stray child processes we may have created
         */
        atexit(waitforchildren);
}


/**
 * Re-Initialize the application - called if a
 * monit daemon receives the SIGHUP signal.
 */
static void do_reinit(bool full) {
        Log_info("Reinitializing Monit -- control file '%s'\n", Run.files.control);

        /* Wait non-blocking for any children that has exited. Since we
         reinitialize any information about children we have setup to wait
         for will be lost. This may create zombie processes until Monit
         itself exit. However, Monit will wait on all children that has exited
         before it itself exit. TODO: Later refactored versions will use a
         globale process table which a sigchld handler can check */
        waitforchildren();

        if (Run.mmonits && isHeartbeatRunning) {
                Sem_signal(Heartbeat_Cond);
                Thread_join(Heartbeat_Thread);
                isHeartbeatRunning = false;
        }

        Run.flags &= ~Run_DoReload;

        /* Stop http interface */
        if (Run.httpd.flags & Httpd_Net || Run.httpd.flags & Httpd_Unix)
                monit_http(Httpd_Stop);

        /* Save the current state (no changes are possible now since the http thread is stopped) */
        if (full)
                State_save();
        State_close();

        /* Run the garbage collector */
        gc();

        if (! parse(Run.files.control)) {
                Log_error("%s stopped -- error parsing configuration file\n", Prog);
                exit(1);
        }

        /* Close the current log */
        Log_close();

        /* Reinstall the log system */
        if (! Log_init())
                exit(1);

        /* Did we find any services ?  */
        if (! Service_List) {
                Log_error("No service has been specified\n");
                exit(0);
        }

        /* Reinitialize Runtime file variables */
        file_init();

        if (! file_createPidFile(Run.files.pid)) {
                Log_error("%s stopped -- cannot create a pid file\n", Prog);
                exit(1);
        }

        /* Update service data from the state repository */
        if (! State_open())
                exit(1);
        State_restore();

        if (full) {
                /* Start http interface */
                if (can_http())
                        monit_http(Httpd_Start);

                /* send the monit startup notification */
                Event_post(Run.system, Event_Instance, State_Changed, Run.system->action_MONIT_START, "Monit reloaded");

                if (Run.mmonits) {
                        Thread_create(Heartbeat_Thread, heartbeat, NULL);
                        isHeartbeatRunning = true;
                }
        }
}


static bool _isMemberOfGroup(Service_T s, ServiceGroup_T g) {
        for (list_t m = g->members->head; m; m = m->next) {
                Service_T member = m->e;
                if (s == member)
                        return true;
        }
        return false;
}


static bool _hasParentInTheSameGroup(Service_T s, ServiceGroup_T g) {
        for (Dependant_T d = s->dependantlist; d; d = d->next ) {
                Service_T parent = Util_getService(d->dependant);
                if (parent && _isMemberOfGroup(parent, g))
                        return true;
        }
        return false;
}


/**
 * Dispatch to the submitted action - actions are program arguments
 */
static void do_action(List_T arguments) {
        char *action = List_pop(arguments);

        Run.flags |= Run_Once;

        if (! action) {
                do_default();
        } else if (IS(action, "start")     ||
                   IS(action, "stop")      ||
                   IS(action, "monitor")   ||
                   IS(action, "unmonitor") ||
                   IS(action, "restart")) {
                char *service = List_pop(arguments);
                if (Run.mygroup || service) {
                        int errors = 0;
                        List_T services = List_new();
                        if (Run.mygroup) {
                                for (ServiceGroup_T sg = Service_Group_List; sg; sg = sg->next) {
                                        if (IS(Run.mygroup, sg->name)) {
                                                for (list_t m = sg->members->head; m; m = m->next) {
                                                        Service_T s = m->e;
                                                        if (IS(action, "restart") && _hasParentInTheSameGroup(s, sg)) {
                                                                DEBUG("Restart of %s skipped -- it'll be handled as part of the dependency chain, as the parent service is member of the same group\n", s->name);
                                                                continue;
                                                        }
                                                        List_append(services, s->name);
                                                }
                                                break;
                                        }
                                }
                                if (List_length(services) == 0) {
                                        List_free(&services);
                                        Log_error("Group '%s' not found\n", Run.mygroup);
                                        exit(1);
                                }
                        } else if (IS(service, "all")) {
                                for (Service_T s = Service_List; s; s = s->next)
                                        List_append(services, s->name);
                        } else {
                                List_append(services, service);
                        }
                        errors = exist_daemon() ? (HttpClient_action(action, services) ? 0 : 1) : control_service_string(services, action);
                        List_free(&services);
                        if (errors)
                                exit(1);
                } else {
                        Log_error("Please specify a service name or 'all' after %s\n", action);
                        exit(1);
                }
        } else if (IS(action, "reload")) {
                Log_info("Reinitializing %s daemon\n", Prog);
                kill_daemon(SIGHUP);
        } else if (IS(action, "status")) {
                char *service = List_pop(arguments);
                if (! HttpClient_status(Run.mygroup, service))
                        exit(1);
        } else if (IS(action, "summary")) {
                char *service = List_pop(arguments);
                if (! HttpClient_summary(Run.mygroup, service))
                        exit(1);
        } else if (IS(action, "report")) {
                char *type = List_pop(arguments);
                if (! HttpClient_report(Run.mygroup, type))
                        exit(1);
        } else if (IS(action, "procmatch")) {
                char *pattern = List_pop(arguments);
                if (! pattern) {
                        printf("Invalid syntax - usage: procmatch \"<pattern>\"\n");
                        exit(1);
                }
                Proc_match(pattern);
        } else if (IS(action, "quit")) {
                kill_daemon(SIGTERM);
        } else if (IS(action, "validate")) {
                if (do_wakeupcall()) {
                        char *service = List_pop(arguments);
                        HttpClient_status(Run.mygroup, service);
                } else {
                        _validateOnce();
                }
                exit(1);
        } else {
                Log_error("Invalid argument -- %s  (-h will show valid arguments)\n", action);
                exit(1);
        }
}


/**
 * Finalize monit
 */
static void do_exit(bool saveState) {
        set_signal_block();
        Run.flags |= Run_Stopped;
        if ((Run.flags & Run_Daemon) && ! (Run.flags & Run_Once)) {
                if (can_http())
                        monit_http(Httpd_Stop);

                if (Run.mmonits && isHeartbeatRunning) {
                        Sem_signal(Heartbeat_Cond);
                        Thread_join(Heartbeat_Thread);
                        isHeartbeatRunning = false;
                }

                Log_info("Monit daemon with pid [%d] stopped\n", (int)getpid());

                /* send the monit stop notification */
                Event_post(Run.system, Event_Instance, State_Changed, Run.system->action_MONIT_STOP, "Monit %s stopped", VERSION);
        }
        if (saveState) {
                State_save();
        }
        if (Process_Table)
                ProcessTable_free(&Process_Table);
        gc();
#ifdef HAVE_OPENSSL
        Ssl_stop();
#endif
        exit(0);
}


/**
 * Default action - become a daemon if defined in the Run object and
 * run validate() between sleeps. If not, just run validate() once.
 * Also, if specified, start the monit http server if in daemon mode.
 */
static void do_default(void) {
        if (Run.flags & Run_Daemon) {
                if (do_wakeupcall())
                        exit(0);

                Run.flags &= ~Run_Once;
                if (can_http()) {
                        if (Run.httpd.flags & Httpd_Net)
                                Log_info("Starting Monit %s daemon with http interface at [%s]:%d\n", VERSION, Run.httpd.socket.net.address ? Run.httpd.socket.net.address : "*", Run.httpd.socket.net.port);
                        else if (Run.httpd.flags & Httpd_Unix)
                                Log_info("Starting Monit %s daemon with http interface at %s\n", VERSION, Run.httpd.socket.unix.path);
                } else {
                        Log_info("Starting Monit %s daemon\n", VERSION);
                }

                if (! (Run.flags & Run_Foreground)) {
                        if (getpid() == 1) {
                                Log_error("Error: Monit is running as process 1 (init) and cannot daemonize\n"
                                          "Please start monit with the -I option to avoid seeing this error\n");
                        } else {
                                daemonize();
                        }
                }

                if (! file_createPidFile(Run.files.pid)) {
                        Log_error("Monit daemon died\n");
                        exit(1);
                }

                if (! State_open())
                        exit(1);
                State_restore();

                atexit(file_finalize);

reload:
                if (Run.startdelay) {
                        if (State_reboot()) {
                                time_t now = Time_monotonic();
                                time_t delay = now + Run.startdelay;

                                Log_info("Monit will delay for %ds on first start after reboot ...\n", Run.startdelay);

                                /* sleep can be interrupted by signal => make sure we paused long enough */
                                while (now < delay) {
                                        sleep((unsigned int)(delay - now));
                                        if (Run.flags & Run_Stopped) {
                                                do_exit(false);
                                        } else if (Run.flags & Run_DoReload) {
                                                do_reinit(false);
                                                goto reload;
                                        }
                                        now = Time_monotonic();
                                }
                        } else {
                                DEBUG("Monit delay %ds skipped -- the system boot time has not changed since last Monit start\n", Run.startdelay);
                        }
                }

                if (can_http())
                        monit_http(Httpd_Start);

                /* send the monit startup notification */
                Event_post(Run.system, Event_Instance, State_Changed, Run.system->action_MONIT_START, "Monit %s started", VERSION);

                if (Run.mmonits) {
                        Thread_create(Heartbeat_Thread, heartbeat, NULL);
                        isHeartbeatRunning = true;
                }

                while (true) {
                        validate();

                        /* In the case that there is no pending action then sleep */
                        if (! (Run.flags & Run_ActionPending) && ! interrupt())
                                sleep(Run.polltime);

                        if (Run.flags & Run_DoWakeup) {
                                Run.flags &= ~Run_DoWakeup;
                                Log_info("Awakened by User defined signal 1\n");
                        }

                        if (Run.flags & Run_Stopped) {
                                do_exit(true);
                        } else if (Run.flags & Run_DoReload) {
                                do_reinit(true);
                        } else {
                                State_saveIfDirty();
                        }
                }
        } else {
                _validateOnce();
        }
}


/**
 * Handle program options - Options set from the commandline
 * takes precedence over those found in the control file
 */
static void handle_options(int argc, char **argv, List_T arguments) {
        int opt;
        int deferred_opt = 0;
        opterr = 0;
        Run.mygroup = NULL;
        const char *shortopts = "+c:d:g:l:p:s:HIirtvVhB";
        while (optind < argc) {
#ifdef HAVE_GETOPT_LONG
                struct option longopts[] = {
                        {"conf",        required_argument,      NULL,   'c'},
                        {"daemon",      required_argument,      NULL,   'd'},
                        {"group",       required_argument,      NULL,   'g'},
                        {"logfile",     required_argument,      NULL,   'l'},
                        {"pidfile",     required_argument,      NULL,   'p'},
                        {"statefile",   required_argument,      NULL,   's'},
                        {"hash",        optional_argument,      NULL,   'H'},
                        {"id",          no_argument,            NULL,   'i'},
                        {"help",        no_argument,            NULL,   'h'},
                        {"resetid",     no_argument,            NULL,   'r'},
                        {"test",        no_argument,            NULL,   't'},
                        {"verbose",     no_argument,            NULL,   'v'},
                        {"batch",       no_argument,            NULL,   'B'},
                        {"interactive", no_argument,            NULL,   'I'},
                        {"version",     no_argument,            NULL,   'V'},
                        {0}
                };
                if ((opt = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1)
#else
                if ((opt = getopt(argc, argv, shortopts)) != -1)
#endif
                {
                        switch (opt) {
                                case 'c':
                                {
                                        char *f = optarg;
                                        char realpath[PATH_MAX] = {};
                                        if (Run.files.control) {
                                                Log_warning("WARNING: The -c option was specified multiple times, only the last value will be used\n");
                                                FREE(Run.files.control);
                                        }
                                        if (f[0] != SEPARATOR_CHAR)
                                                f = File_getRealPath(optarg, realpath);
                                        if (! f)
                                                THROW(AssertException, "The control file '%s' does not exist at %s", Str_trunc(optarg, 80), Dir_cwd((char[STRLEN]){}, STRLEN));
                                        if (! File_isFile(f))
                                                THROW(AssertException, "The control file '%s' is not a file", Str_trunc(f, 80));
                                        if (! File_isReadable(f))
                                                THROW(AssertException, "The control file '%s' is not readable", Str_trunc(f, 80));
                                        Run.files.control = Str_dup(f);
                                        break;
                                }
                                case 'd':
                                {
                                        Run.flags |= Run_Daemon;
                                        if (sscanf(optarg, "%d", &Run.polltime) != 1 || Run.polltime < 1) {
                                                Log_error("Option -%c requires a natural number\n", opt);
                                                exit(1);
                                        }
                                        break;
                                }
                                case 'g':
                                {
                                        if (Run.mygroup) {
                                                Log_warning("WARNING: The -g option was specified multiple times, only the last value will be used\n");
                                                FREE(Run.mygroup);
                                        }
                                        Run.mygroup = Str_dup(optarg);
                                        break;
                                }
                                case 'l':
                                {
                                        if (Run.files.log) {
                                                Log_warning("WARNING: The -l option was specified multiple times, only the last value will be used\n");
                                                FREE(Run.files.log);
                                        }
                                        Run.files.log = Str_dup(optarg);
                                        if (IS(Run.files.log, "syslog"))
                                                Run.flags |= Run_UseSyslog;
                                        Run.flags |= Run_Log;
                                        break;
                                }
                                case 'p':
                                {
                                        if (Run.files.pid) {
                                                Log_warning("WARNING: The -p option was specified multiple times, only the last value will be used\n");
                                                FREE(Run.files.pid);
                                        }
                                        Run.files.pid = Str_dup(optarg);
                                        break;
                                }
                                case 's':
                                {
                                        if (Run.files.state) {
                                                Log_warning("WARNING: The -s option was specified multiple times, only the last value will be used\n");
                                                FREE(Run.files.state);
                                        }
                                        Run.files.state = Str_dup(optarg);
                                        break;
                                }
                                case 'I':
                                {
                                        Run.flags |= Run_Foreground;
                                        break;
                                }
                                case 'i':
                                {
                                        deferred_opt = 'i';
                                        break;
                                }
                                case 'r':
                                {
                                        deferred_opt = 'r';
                                        break;
                                }
                                case 't':
                                {
                                        deferred_opt = 't';
                                        break;
                                }
                                case 'v':
                                {
                                        Run.debug++;
                                        Bootstrap_setDebugHandler(Log_vdebug);
                                        break;
                                }
                                case 'H':
                                {
                                        if (argc > optind)
                                                Checksum_printHash(argv[optind]);
                                        else
                                                Checksum_printHash(NULL);
                                        exit(0);
                                        break;
                                }
                                case 'V':
                                {
                                        version();
                                        exit(0);
                                        break;
                                }
                                case 'h':
                                {
                                        help();
                                        exit(0);
                                        break;
                                }
                                case 'B':
                                {
                                        Run.flags |= Run_Batch;
                                        break;
                                }
                                case '?':
                                {
                                        switch (optopt) {
                                                case 'c':
                                                case 'd':
                                                case 'g':
                                                case 'l':
                                                case 'p':
                                                case 's':
                                                {
                                                        Log_error("Option -- %c requires an argument\n", optopt);
                                                        break;
                                                }
                                                default:
                                                {
                                                        Log_error("Invalid option -- %c  (-h will show valid options)\n", optopt);
                                                }
                                        }
                                        exit(1);
                                }
                        }
                } else {
                        List_append(arguments, argv[optind++]);
                }
        }
        /* Handle deferred options to make arguments to the program positional
         independent. These options are handled last, here as they represent exit
         points in the application and the control-file might be set with -c and
         these options need to respect the new control-file location as they call
         do_init */
        switch (deferred_opt) {
                case 't':
                {
                        do_init(); // Parses control file and initialize program, exit on error
                        printf("Control file syntax OK\n");
                        exit(0);
                        break;
                }
                case 'r':
                {
                        do_init();
                        assert(Run.id);
                        printf("Reset Monit Id? [y/N]> ");
                        if (tolower(getchar()) == 'y') {
                                File_delete(Run.files.id);
                                Util_monitId(Run.files.id);
                                kill_daemon(SIGHUP); // make any running Monit Daemon reload the new ID-File
                        }
                        exit(0);
                        break;
                }
                case 'i':
                {
                        do_init();
                        assert(Run.id);
                        printf("Monit ID: %s\n", Run.id);
                        exit(0);
                        break;
                }
        }
}


/**
 * Print the program's help message
 */
static void help(void) {
        printf(
               "Usage: %s [options]+ [command]\n"
               "Options are as follows:\n"
               " -c file       Use this control file\n"
               " -d n          Run as a daemon once per n seconds\n"
               " -g name       Set group name for monit commands\n"
               " -l logfile    Print log information to this file\n"
               " -p pidfile    Use this lock file in daemon mode\n"
               " -s statefile  Set the file monit should write state information to\n"
               " -I            Do not run in background (needed when run from init)\n"
               " --id          Print Monit's unique ID\n"
               " --resetid     Reset Monit's unique ID. Use with caution\n"
               " -B            Batch command line mode (do not output tables or colors)\n"
               " -t            Run syntax check for the control file\n"
               " -v            Verbose mode, work noisy (diagnostic output)\n"
               " -vv           Very verbose mode, same as -v plus log stacktrace on error\n"
               " -H [filename] Print SHA1 and MD5 hashes of the file or of stdin if the\n"
               "               filename is omitted; monit will exit afterwards\n"
               " -V            Print version number and patchlevel\n"
               " -h            Print this text\n"
               "Optional commands are as follows:\n"
               " start all             - Start all services\n"
               " start <name>          - Only start the named service\n"
               " stop all              - Stop all services\n"
               " stop <name>           - Stop the named service\n"
               " restart all           - Stop and start all services\n"
               " restart <name>        - Only restart the named service\n"
               " monitor all           - Enable monitoring of all services\n"
               " monitor <name>        - Only enable monitoring of the named service\n"
               " unmonitor all         - Disable monitoring of all services\n"
               " unmonitor <name>      - Only disable monitoring of the named service\n"
               " reload                - Reinitialize monit\n"
               " status [name]         - Print full status information for service(s)\n"
               " summary [name]        - Print short status information for service(s)\n"
               " report [up|down|..]   - Report state of services. See manual for options\n"
               " quit                  - Kill the monit daemon process\n"
               " validate              - Check all services and start if not running\n"
               " procmatch <pattern>   - Test process matching pattern\n",
               Prog);
}

/**
 * Print version information
 */
static void version(void) {
        printf("This is Monit version %s\n", VERSION);
        printf("Built with");
#ifndef HAVE_OPENSSL
        printf("out");
#endif
        printf(" ssl, with");
#ifndef HAVE_IPV6
        printf("out");
#endif
        printf(" ipv6, with");
#ifndef HAVE_LIBZ
        printf("out");
#endif
        printf(" compression, with");
#ifndef HAVE_LIBPAM
        printf("out");
#endif
        printf(" pam and with");
#ifndef HAVE_LARGEFILES
        printf("out");
#endif
        printf(" large files\n");
        printf("Copyright (C) 2001-2023 Tildeslash Ltd. All Rights Reserved.\n");
}


/**
 * M/Monit heartbeat thread
 */
static void *heartbeat(__attribute__ ((unused)) void *args) {
        set_signal_block();
        Log_info("M/Monit heartbeat started\n");
        LOCK(Heartbeat_Mutex)
        {
                while (! interrupt()) {
                        MMonit_send(NULL);
                        struct timespec wait = {.tv_sec = Time_now() + Run.polltime};
                        Sem_timeWait(Heartbeat_Cond, Heartbeat_Mutex, wait);
                }
        }
        END_LOCK;
#ifdef HAVE_OPENSSL
        Ssl_threadCleanup();
#endif
        Log_info("M/Monit heartbeat stopped\n");
        return NULL;
}


/**
 * Signalhandler for a daemon reload call
 */
static void do_reload(__attribute__ ((unused)) int sig) {
        Run.flags |= Run_DoReload;
}


/**
 * Signalhandler for monit finalization
 */
static void do_destroy(__attribute__ ((unused)) int sig) {
        Run.flags |= Run_Stopped;
}


/**
 * Signalhandler for a daemon wakeup call
 */
static void do_wakeup(__attribute__ ((unused)) int sig) {
        Run.flags |= Run_DoWakeup;
}


/* A simple non-blocking reaper to ensure that we wait-for and reap all/any stray child processes
 we may have created and not waited on, so we do not create any zombie processes at exit */
static void waitforchildren(void) {
        while (waitpid(-1, NULL, WNOHANG) > 0) ;
}
