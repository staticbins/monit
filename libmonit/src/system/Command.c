/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
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


#include "Config.h"

#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

#ifdef HAVE_USERSEC_H
#include <usersec.h>
#endif

#include "Str.h"
#include "Dir.h"
#include "File.h"
#include "List.h"
#include "system/Net.h"
#include "StringBuffer.h"

#include "system/System.h"
#include "system/Time.h"
#include "system/Command.h"


/**
 * Implementation of the Command and Process interfaces.
 *
 * @author http://www.tildeslash.com/
 * @see https://mmonit.com
 * @file
 */



// MARK: - Definitions


#define T Command_T
struct T {
        uid_t uid;
        gid_t gid;
        List_T env;
        List_T args;
        mode_t umask;
        char *working_directory;
};

struct Process_T {
        pid_t pid;
        int status;
        char *name;
        char *arg0;
        bool isdetached;
        int ctrl_pipe[2];
        int stdin_pipe[2];
        int stdout_pipe[2];
        int stderr_pipe[2];
        InputStream_T in;
        InputStream_T err;
        OutputStream_T out;
};

struct _usergroups {
        int ngroups;
        gid_t groups[NGROUPS_MAX];
};

// Some POSIX systems does not define environ explicit
extern char **environ;

// Default umask for the sub-process
#define DEFAULT_UMASK 022


// MARK: - Private methods


// Search the env list and return the pointer to the name (in the list)
// if found, otherwise NULL.
static inline char *_findEnv(T C, const char *name, size_t len) {
        assert(len >= 0);
        for (_list_t p = C->env->head; p; p = p->next) {
                if ((strncmp(p->e, name, len) == 0))
                        if (((char*)p->e)[len] == '=') // Ensure that name is not just a sub-string
                                return p->e;
        }
        return NULL;
}


// Remove env identified by name
static inline void _removeEnv(T C, const char *name) {
        char *e = _findEnv(C, name, strlen(name));
        if (e) {
                List_remove(C->env, e);
                FREE(e);
        }
}


// Free each string in a list of strings
static void _freeElementsIn(List_T l) {
        while (List_length(l) > 0) {
                char *s = List_pop(l);
                FREE(s);
        }
}


// Build the Command args list. The list represent the array sent
// to execv and the List contains the following entries: args[0] is the
// path to the program, the rest are optional arguments to the program
static void _buildArgs(T C, const char *path, va_list ap) {
        List_append(C->args, Str_dup(path));
        va_list ap_copy;
        va_copy(ap_copy, ap);
        for (char *a = va_arg(ap_copy, char *); a; a = va_arg(ap_copy, char *))
                List_append(C->args, Str_dup(a));
        va_end(ap_copy);
}


// Returns an array of program args. Should only be called in the child
static inline char **_args(T C) {
        assert(C);
        return (char**)List_toArray(C->args);
}


// Returns an array of program environment. Must only be called in the child.
// If the environment list is empty, just return the global environ variable.
// Otherwise don't copy, but add references to environ entries unless already set
static inline char **_env(T C) {
        assert(C);
        if (List_length(C->env) == 0)
                return environ;
        for (int i = 0; environ[i]; i++) {
                size_t len = strchr(environ[i], '=') - environ[i];
                if (_findEnv(C, environ[i], len))
                        continue;
                List_append(C->env, environ[i]);
        }
        return (char**)List_toArray(C->env);
}


#ifndef HAVE_GETGROUPLIST
#ifdef AIX
static int getgrouplist(const char *name, int basegid, int *groups, int *ngroups) {
        int rv = -1;

        // Open the user database
        if (setuserdb(S_READ) != 0) {
                DEBUG("Cannot open user database -- %s\n", System_getError(errno));
                goto fail4;
        }

        // Get administrative domain for the user so we can lookup the group membership in the correct database (files, LDAP, etc).
        char *registry;
        if (getuserattr((char *)name, S_REGISTRY, &registry, SEC_CHAR) == 0 && setauthdb(registry, NULL) != 0) {
                DEBUG("Administrative domain switch to %s for user %s failed -- %s\n", registry, name, System_getError(errno));
                goto fail3;
        }

        // Get the list of groups for the named user
        char *groupList = getgrset(name);
        if (! groupList) {
                DEBUG("Cannot get groups for user %s\n", name);
                goto fail2;
        }

        // Add the base GID
        int count = 1;
        groups[0] = basegid;

        // Parse the comma separated list of groups
        char *lastGroup = NULL;
        for (char *currentGroup = strtok_r(groupList, ",", &lastGroup); currentGroup; currentGroup = strtok_r(NULL, ",", &lastGroup)) {
                gid_t gid = (gid_t)Str_parseInt(currentGroup);
                // Add the GID to the list (unless it's basegid, which we pushed to the beginning of groups list already)
                if (gid != basegid) {
                        if (count == *ngroups) {
                                // Maximum groups reached (error will be indicated by -1 return value, but we return as many groups as possible in the list)
                                goto fail1;
                        }
                        groups[count++] = gid;
                }
        }

        // Success
        rv = 0;
        *ngroups = count;

error1:
        FREE(groupList);

error2:
        // Restore the administrative domain
        setauthdb(NULL, NULL);

error3:
        // Close the user database
        if (enduserdb() != 0) {
                DEBUG("Cannot close user database -- %s\n", System_getError(errno));
        }

error4:
        return rv;
}
#else
#error "getgrouplist missing"
#endif
#endif


// Block all signals and make the current thread not cancellable
static struct _block {sigset_t sigmask; int threadstate;} _block(void) {
        sigset_t b;
        sigfillset(&b);
        struct _block block = {};
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &block.threadstate);
        pthread_sigmask(SIG_BLOCK, &b, &block.sigmask);
        return block;
}


// Un-Block signals and make the current thread cancellable again
static void _unblock(struct _block *block) {
        pthread_sigmask(SIG_SETMASK, &block->sigmask, NULL);
        pthread_setcancelstate(block->threadstate, 0);
}


// Reset all signals to default, except for SIGHUP and SIGPIPE which
// are set to SIG_IGN
static void _resetSignals(void) {
    sigset_t mask;
    sigemptyset(&mask);
    pthread_sigmask(SIG_SETMASK, &mask, 0);
    struct sigaction sa_default = {.sa_handler = SIG_DFL};
    struct sigaction sa_ignore = {.sa_handler = SIG_IGN};
    for (int i = 1; i < NSIG; ++i) {
        if (i == SIGKILL || i == SIGSTOP)
            continue;
        if (i == SIGHUP || i == SIGPIPE)
                sigaction(i, &sa_ignore, NULL);
        else
                sigaction(i, &sa_default, NULL);
    }
}


struct _usergroups *_getUserGroups(T C, struct _usergroups *ug) {
        // There are no threads in the child so we can use
        // the simpler getpwuid() instead of getpwuid_r()
        struct passwd *result = getpwuid(C->uid);
        if (!result)
                return NULL;
        Command_setEnv(C, "HOME", result->pw_dir);
        if (getgrouplist(result->pw_name, C->gid,
#ifdef __APPLE__
                         (int *)ug->groups,
#else
                         ug->groups,
#endif
                         &ug->ngroups) < 0)
                return NULL;
        return ug;
}


// Close both ends of the given pipe if not already closed
static void _closePipe(int pipe[static 2]) {
    for (int i = 0; i < 2; i++) {
        if (pipe[i] >= 0) {
            close(pipe[i]);
            pipe[i] = -1;
        }
    }
}


// MARK: - Process_T Private methods


static void Process_closeCtrlPipe(Process_T P) {
        _closePipe(P->ctrl_pipe);
}


// Close pipes in process, except ctrl_pipe which are used during
// child setup before calling exec
static void Process_closePipes(Process_T P) {
        _closePipe(P->stdin_pipe);
        _closePipe(P->stdout_pipe);
        _closePipe(P->stderr_pipe);
}


// Setup a controller pipe to be used between parent and child to
// report any errors during the setup phase or if execve fails
static int Process_createCtrlPipe(Process_T P) {
        int status = 0;
        // Not all POSIX systems have pipe2(), like macOS,
        if (pipe(P->ctrl_pipe) < 0) {
                status = -errno;
                DEBUG("Command: ctrl pipe(2) failed -- %s\n", System_lastError());
                return status;
        }
        for (int i = 0; i < 2; i++) {
                if (fcntl(P->ctrl_pipe[i], F_SETFD, FD_CLOEXEC) < 0) {
                        status = -errno;
                        DEBUG("Command: ctrl fcntl(2) FD_CLOEXEC failed -- %s\n", System_lastError());
                        _closePipe(P->ctrl_pipe);
                        return status;
                }
        }
        return 0;
}


// Create pipes for communication between parent and child process
static int Process_createPipes(Process_T P) {
        int status = Process_createCtrlPipe(P);
        if (status < 0)
                return status;
        if (pipe(P->stdin_pipe) < 0 || pipe(P->stdout_pipe) < 0 || pipe(P->stderr_pipe) < 0) {
                status = -errno;
                DEBUG("Command: pipe(2) failed -- %s\n", System_lastError());
                Process_closePipes(P);
                return status;
        }
        return 0;
}


// Setup stdio pipes in subprocess. We need not close pipes as the child
// process will exit if this fails
static bool Process_setupChildPipes(Process_T P) {
        close(P->stdin_pipe[1]);   // close write end
        if (P->stdin_pipe[0] != STDIN_FILENO) {
                if (dup2(P->stdin_pipe[0],  STDIN_FILENO) != STDIN_FILENO)
                        return false;
        }
        close(P->stdout_pipe[0]);  // close read end
        if (P->stdout_pipe[1] != STDOUT_FILENO) {
                if (dup2(P->stdout_pipe[1], STDOUT_FILENO) != STDOUT_FILENO)
                        return false;
        }
        close(P->stderr_pipe[0]);  // close read end
        if (P->stderr_pipe[1] != STDERR_FILENO) {
                if (dup2(P->stderr_pipe[1], STDERR_FILENO) != STDERR_FILENO)
                        return false;
        }
        return true;
}


// Setup stdio pipes in parent process for communication with the subprocess
static void Process_setupParentPipes(Process_T P) {
        close(P->stdin_pipe[0]);  // close read end
        close(P->stdout_pipe[1]); // close write end
        close(P->stderr_pipe[1]); // close write end
        Net_setNonBlocking(P->stdin_pipe[1]);
        Net_setNonBlocking(P->stdout_pipe[0]);
        Net_setNonBlocking(P->stderr_pipe[0]);
}


// Release stdio streams
static void Process_closeStreams(Process_T P) {
        if (P->in) InputStream_free(&P->in);
        if (P->err) InputStream_free(&P->err);
        if (P->out) OutputStream_free(&P->out);
}


static inline void _setstatus(Process_T P) {
        if (WIFEXITED(P->status))
                P->status = WEXITSTATUS(P->status);
        else if (WIFSIGNALED(P->status))
                P->status = WTERMSIG(P->status);
        else if (WIFSTOPPED(P->status))
                P->status = WSTOPSIG(P->status);
}


static Process_T Process_new(void) {
        Process_T P;
        NEW(P);
        P->pid = -1;
        P->status = -1;
        return P;
}


// MARK: - Process_T Public methods


void Process_free(Process_T *P) {
        assert(P && *P);
        if (!(*P)->isdetached) {
                if (Process_isRunning(*P)) {
                        Process_kill(*P);
                        Process_waitFor(*P);
                }
                Process_detach(*P);
        }
        FREE((*P)->arg0);
        FREE((*P)->name);
        FREE(*P);
}


// Close pipes and streams to the sub-process. Because we ignored SIGPIPE when
// creating the sub-process it should not recieve SIGPIPE if it tries to write
// to one of its (now broken) output pipes. A proper daemon process will also
// normally redirect stdio to /dev/null and instead write to a log file after
// its initial setup phase
void Process_detach(Process_T P) {
        assert(P);
        if (!P->isdetached) {
                P->isdetached = true;
                Process_closeStreams(P);
                Process_closePipes(P);
        }
}


bool Process_isdetached(Process_T P) {
        assert(P);
        return P->isdetached;
}


pid_t Process_pid(Process_T P) {
        assert(P);
        return P->pid;
}


int Process_waitFor(Process_T P) {
        assert(P);
        if (P->status < 0) {
                int r;
                do
                        r = waitpid(P->pid, &P->status, 0); // Wait blocking
                while (r == -1 && errno == EINTR);
                if (r != P->pid)
                        P->status = -1;
                else
                        _setstatus(P);
        }
        return P->status;
}


int Process_exitStatus(Process_T P) {
        assert(P);
        if (P->status < 0) {
                int r;
                do
                        r = waitpid(P->pid, &P->status, WNOHANG); // Wait non-blocking
                while (r < 0 && errno == EINTR);
                if (r == 0) // Process is still running
                        P->status = -1;
                else
                        _setstatus(P);
        }
        return P->status;
}


void Process_setExitStatus(Process_T P, int status) {
        assert(P);
        P->status = status;
        _setstatus(P);
}


bool Process_isRunning(Process_T P) {
        assert(P);
        if (P->pid == -1)
                return false;
        return Process_exitStatus(P) < 0;
}


OutputStream_T Process_outputStream(Process_T P) {
        assert(P);
        if (P->isdetached)
                return NULL;
        if (! P->out)
                P->out = OutputStream_new(P->stdin_pipe[1]);
        return P->out;
}


InputStream_T Process_inputStream(Process_T P) {
        assert(P);
        if (P->isdetached)
                return NULL;
        if (! P->in)
                P->in = InputStream_new(P->stdout_pipe[0]);
        return P->in;
}


InputStream_T Process_errorStream(Process_T P) {
        assert(P);
        if (P->isdetached)
                return NULL;
        if (! P->err)
                P->err = InputStream_new(P->stderr_pipe[0]);
        return P->err;
}


const char *Process_arg0(Process_T P) {
        assert(P);
        return P->arg0;
}


const char *Process_name(Process_T P) {
        assert(P);
        return P->name;

}


void Process_setName(Process_T P, const char *name) {
        assert(P);
        STR_SET(P->name, name);
}


bool Process_terminate(Process_T P) {
        assert(P);
        return (kill(P->pid, SIGTERM) == 0);
}


bool Process_kill(Process_T P) {
        assert(P);
        return (kill(P->pid, SIGKILL) == 0);
}


// MARK: - Public methods


T _Command_new(const char *path, ...) {
        T C;
        assert(path);
        if (! File_exist(path))
                THROW(AssertException, "File '%s' does not exist", path);
        NEW(C);
        C->env = List_new();
        C->args = List_new();
        C->umask = DEFAULT_UMASK;
        va_list ap;
        va_start(ap, path);
        _buildArgs(C, path, ap);
        va_end(ap);
        return C;
}


void Command_free(T *C) {
        assert(C && *C);
        _freeElementsIn((*C)->args);
        List_free(&(*C)->args);
        _freeElementsIn((*C)->env);
        List_free(&(*C)->env);
        FREE((*C)->working_directory);
        FREE(*C);
}


void Command_appendArgument(T C, const char *argument) {
        assert(C);
        if (argument)
                List_append(C->args, Str_dup(argument));
}


void Command_setUid(T C, uid_t uid) {
        assert(C);
        if (getuid() != 0)
                THROW(AssertException, "Only the super user can switch uid");
        C->uid = uid;
}


uid_t Command_uid(T C) {
        assert(C);
        return C->uid;
}


void Command_setGid(T C, gid_t gid) {
        assert(C);
        if (getuid() != 0)
                THROW(AssertException, "Only the super user can switch gid");
        C->gid = gid;
}


gid_t Command_gid(T C) {
        assert(C);
        return C->gid;
}


void Command_setUmask(T C, mode_t umask) {
        assert(C);
        C->umask = umask;
}


mode_t Command_umask(T C) {
        assert(C);
        return C->umask;
}


// Set the sub-process working directory. If NULL (the default) the sub-process
// will inherit the calling process's current directory
void Command_setDir(T C, const char *dir) {
        assert(C);
        if (dir) {
                if (! File_isDirectory(dir))
                        THROW(AssertException, "The new working directory '%s' is not a directory", dir);
                if (! File_isExecutable(dir))
                        THROW(AssertException, "The new working directory '%s' is not accessible", dir);
        }
        FREE(C->working_directory);
        C->working_directory = File_removeTrailingSeparator(Str_dup(dir));
}


const char *Command_dir(T C) {
        assert(C);
        return C->working_directory;
}


// Env variables are stored in the environment list as "name=value" strings
void Command_setEnv(Command_T C, const char *name, const char *value) {
        assert(C);
        assert(name);
        _removeEnv(C, name);
        List_append(C->env, Str_cat("%s=%s", name, value ? value : ""));
}


// Env variables are stored in the environment list as "name=value" strings
void Command_vSetEnv(T C, const char *name, const char *value, ...) {
        assert(C);
        assert(name);
        _removeEnv(C, name);
        char *t = NULL;
        if (STR_DEF(value)) {
                va_list ap;
                va_start(ap, value);
                t = Str_vcat(value, ap);
                va_end(ap);
        }
        List_append(C->env, Str_cat("%s=%s", name, t?t:""));
        FREE(t);
}


// Returns the value part from a "name=value" environment string
const char *Command_env(T C, const char *name) {
        assert(C);
        assert(name);
        size_t len = strlen(name);
        char *e = _findEnv(C, name, len);
        if (e)
                return e + len + 1;
        return NULL;
}


List_T Command_command(T C) {
        assert(C);
        return C->args;
}


// MARK: - Execute


// Setup and exec the child process
static void Process_exec(Process_T P, T C) {
        int status = 0;
        _resetSignals();
        errno = 0;
        if (C->working_directory) {
                if (! Dir_chdir(C->working_directory))
                        goto fail;
        }
        if (setsid() < 0)
                goto fail;
        if (!Process_setupChildPipes(P))
                goto fail;
        int descriptors = open("/dev/null", O_RDWR);
        if (descriptors < 4)
                descriptors = System_descriptors(256);
        else
                descriptors += 1;
        for (int i = 3; i < descriptors; i++) {
                if (i != P->ctrl_pipe[1])
                        close(i);
        }
        if (C->gid) {
                if (setgid(C->gid) < 0)
                        goto fail;
                if (getgid() != C->gid) {
                        errno = EPERM;
                        goto fail;
                }
        }
        if (C->uid) {
                struct _usergroups ug = {.groups = {}, .ngroups = NGROUPS_MAX};
                if (!_getUserGroups(C, &ug))
                        goto fail;
                if (setgroups(ug.ngroups, ug.groups) < 0)
                        goto fail;
                if (setuid(C->uid) < 0)
                        goto fail;
                if (getuid() != C->uid) {
                        errno = EPERM;
                        goto fail;
                }
        }
        umask(C->umask);
        char **args = _args(C);
        execve(args[0], args, _env(C));
fail:
        status = errno;
        if (status != 0)
                while (write(P->ctrl_pipe[1], &status, sizeof status) < 0);
        _exit(127);
}


// If the child process succeeded in calling execve, status is 0
static void Process_ctrl(Process_T P, int *status) {
        close(P->ctrl_pipe[1]);
        if (read(P->ctrl_pipe[0], status, sizeof *status) != sizeof *status)
                *status = 0;
        else waitpid(P->pid, &(int){0}, 0);
}


/*
 The Execute function.

 We do not use posix_spawn(2) because it's not well suited for creating
 long-running daemon processes. Although posix_spawn is more efficient, its
 limitations makes it problematic for our use. Specifically:

 - The POSIX standard does not support calling setsid(2) in the child
   process, which is important to have the child detach from the controlling
   terminal. Some implementations do support setsid() unofficially via the
   flag POSIX_SPAWN_SETSID, but this is not standardized.
 - posix_spawn does not inherently handle the transition of privileges
   associated with setuid/setgid programs.
 - Closing "all" descriptors in the child before calling exec is not directly
   supported. While there is limited support for closing specific descriptors,
   there is no straightforward way to unconditionally close all potentially
   open descriptors.
 - There is no support for changing the working directory (chdir) in the child
   process before exec is called. This limitation can be significant, especially
   in daemon processes where changing to a specific directory is often required.
 - Inability to Change umask: posix_spawn lacks support for changing the file
   mode creation mask (umask) in the child process.

 Traditional fork/exec offers a bit more control and flexibility. With modern OSs
 supporting Copy-On-Write (COW), the issue of unnecessary memory address space
 duplication in the child before calling exec becomes less significant, albeit
 still an annoyance.
 */
Process_T Command_execute(T C) {
        assert(C);
        struct _block block = _block();
        Process_T P = Process_new();
        int status = Process_createPipes(P);
        if (status < 0) {
                status = -status;
                goto fail;
        }
        if ((P->pid = fork()) < 0) {
                status = errno;
        } else if (P->pid == 0) {
                Process_exec(P, C);
        } else {
                Process_ctrl(P, &status);
        }
fail:
        Process_closeCtrlPipe(P);
        if (status != 0) {
                DEBUG("Command: failed -- %s\n", System_getError(status));
                Process_free(&P);
        } else {
                Process_setupParentPipes(P);
                P->arg0 = Str_dup(C->args->head->e);
        }
        _unblock(&block);
        errno = status;
        return P;
}
