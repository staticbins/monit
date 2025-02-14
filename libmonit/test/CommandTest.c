#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>

#include "Bootstrap.h"
#include "Str.h"
#include "List.h"
#include "File.h"
#include "system/System.h"
#include "system/Command.h"
#include "system/Time.h"

/**
 * Command.c unit tests.
 */


static void onExec(Process_T P) {
        assert(P);
        char buf[STRLEN];
        // Child process info
        printf("\tSubprocess ((pid=%d)\n", Process_pid(P));
        InputStream_T in = Process_inputStream(P);
        OutputStream_T out = Process_outputStream(P);
        InputStream_T err = Process_errorStream(P);
        printf("\tSub-Process is %s\n", Process_isRunning(P) ? "running" : "not running");
        printf("\tCommunication with child:\n");
        if (! InputStream_readLine(in, buf, STRLEN)) {
                InputStream_readLine(err, buf, STRLEN);
                printf("\tError in script: %s\n", Str_chomp(buf));
        } else {
                printf("\t%s", buf);
                OutputStream_print(out, "Elessar Telcontar\n");
                assert(OutputStream_flush(out) > 0);
                char *line = InputStream_readLine(in, buf, STRLEN);
                assert(line);
                printf("\t%s", line);
        }
        printf("\tProcess exited with status: %d\n", Process_waitFor(P));
        Process_free(&P);
}


static void onTerminate(Process_T P) {
        assert(P);
        printf("\tTest terminate subprocess ((pid=%d)\n", Process_pid(P));
        assert(Process_isRunning(P));
        assert(Process_terminate(P));
        printf("\tProcess exited with status: %d\n", Process_waitFor(P));
        assert(Process_exitStatus(P) == SIGTERM);
        Process_free(&P);
}


static void onKill(Process_T P) {
        assert(P);
        printf("\tTest kill subprocess ((pid=%d)\n", Process_pid(P));
        assert(Process_isRunning(P));
        assert(Process_kill(P));
        printf("\tProcess exited with status: %d\n", Process_waitFor(P));
        assert(Process_exitStatus(P) == SIGKILL);
        Process_free(&P);
}


static void onEnv(Process_T P) {
        assert(P);
        char buf[STRLEN];
        InputStream_T in = Process_inputStream(P);
        assert(InputStream_readLine(in, buf, STRLEN));
        assert(Str_isEqual(Str_chomp(buf), "Ylajali"));
        // Assert that sub-process environment is not set in main process
        assert(! getenv("SULT"));
        printf("\tEnvironment Variable in sub-process only: $SULT = %s\n", buf);
        Process_free(&P);
        assert(! P);
}

static void onDetach(Process_T P) {
        assert(P);
        File_delete("/tmp/ondetach");
        // Assert the process is running, blocking on read
        assert(Process_isRunning(P));
        // Close pipes and streams, this will cause read in the script to return with eof
        Process_detach(P);
        assert(Process_isdetached(P));
        // Streams should be closed and not available after a detach
        assert(Process_inputStream(P) == NULL);
        // Assert that the script exited cleanly
        assert(Process_waitFor(P) == 0);
        Process_free(&P);
        // Finally assert that the script did continue and wrote this file
        assert(File_delete("/tmp/ondetach"));
}


int main(void) {

        Bootstrap(); // Need to initialize library

        printf("============> Start Command Tests\n\n");


        printf("=> Test1: create/destroy\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "ps -aef|grep monit");
                assert(c);
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: set and get uid/gid\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "ps -aef|grep monit");
                // Check that default is 0
                assert(Command_uid(c) == 0);
                assert(Command_gid(c) == 0);
                if (getuid() == 0) {
                        Command_setUid(c,42);
                        assert(Command_uid(c) == 42);
                        Command_setGid(c,148);
                        assert(Command_gid(c) == 148);
                        Command_free(&c);
                } else {
                        TRY
                        {
                                printf("\tNot running as root. Checking exception instead: ");
                                Command_setUid(c,42);
                                printf("AssertException not thrown\n");
                                exit(1);
                        }
                        CATCH (AssertException)
                                printf("ok\n");
                        END_TRY;
                }
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test4: set and get env\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "ps -aef|grep monit");
                // Set and get env string
                Command_setEnv(c, "PATH", "/usr/bin");
                Command_setEnv(c, "SHELL", "/bin/bash");
                Command_setEnv(c, "PAT", "Carroll");
                assert(Str_isEqual(Command_env(c, "PATH"), "/usr/bin"));
                assert(Str_isEqual(Command_env(c, "SHELL"), "/bin/bash"));
                assert(Str_isEqual(Command_env(c, "PAT"), "Carroll"));
                // Empty and NULL value
                Command_setEnv(c, "PATH", "");
                Command_setEnv(c, "SHELL", NULL);
                assert(Str_isEqual(Command_env(c, "PATH"), ""));
                assert(Str_isEqual(Command_env(c, "SHELL"), ""));
                // Unknown variable should result in NULL
                assert(Command_env(c, "UKNOWNVARIABLE") == NULL);
                // vSetEnv
                Command_vSetEnv(c, "PID", "%ld", (long)getpid());
                assert(Str_parseLLong(Command_env(c, "PID")) > 1);
                Command_vSetEnv(c, "ZERO", NULL);
                assert(Str_isEqual(Command_env(c, "ZERO"), ""));
                Command_free(&c);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: set and get Command\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "ps -aef|grep monit");
                List_T l = Command_command(c);
                assert(Str_isEqual(l->head->e, "/bin/sh"));
                assert(Str_isEqual(l->head->next->e, "-c"));
                assert(Str_isEqual(l->head->next->next->e, "ps -aef|grep monit"));
                Command_free(&c);
        }
        printf("=> Test5: OK\n\n");

        printf("=> Test6: Append arguments\n");
        {
                Command_T c = Command_new("/bin/ls");
                Command_appendArgument(c, "-l");
                Command_appendArgument(c, "-t");
                Command_appendArgument(c, "-r");
                List_T l = Command_command(c);
                assert(Str_isEqual(l->head->e, "/bin/ls"));
                assert(Str_isEqual(l->head->next->e, "-l"));
                assert(Str_isEqual(l->head->next->next->e, "-t"));
                assert(Str_isEqual(l->head->next->next->next->e, "-r"));
                assert(l->head->next->next->next->next == NULL);
                Command_free(&c);
        }
        printf("=> Test6: OK\n\n");

        printf("=> Test7: execute invalid program\n");
        {
                // Program producing error
                Command_T c = Command_new("/bin/sh", "-c", "not_a_program;");
                Command_setDir(c, "/");
                printf("\tThis should produce an error:\n");
                onExec(Command_execute(c));
                Command_free(&c);
                // Nonexistent program
                TRY
                {
                        Command_new("/bla/bla/123");
                        exit(1);
                }
                CATCH (AssertException)
                END_TRY;
        }
        printf("=> Test7: OK\n\n");

        printf("=> Test8: execute valid program\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "echo \"Please enter your name:\";read name;echo \"Hello $name\";");
                onExec(Command_execute(c));
                Command_free(&c);
        }
        printf("=> Test8: OK\n\n");

        printf("=> Test9: terminate sub-process\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "exec sleep 30;");
                onTerminate(Command_execute(c));
                Command_free(&c);
        }
        printf("=> Test9: OK\n\n");

        printf("=> Test10: kill sub-process\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "trap 1 2 15; sleep 30; ");
                onKill(Command_execute(c));
                Command_free(&c);
        }
        printf("=> Test10: OK\n\n");

        printf("=> Test11: environment in sub-process\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "echo $SULT");
                // Set environment in sub-process only
                Command_setEnv(c, "SULT", "Ylajali");
                onEnv(Command_execute(c));
                Command_free(&c);
        }
        printf("=> Test11: OK\n\n");

        printf("=> Test12: on execve(2) error\n");
        {
                // Executing a directory should produce an execve error
                Command_T c = Command_new("/tmp");
                Process_T p = Command_execute(c);
                assert(! p);
                Command_free(&c);
                printf("\tOK, got execve error -- %s\n", System_lastError());
        }
        printf("=> Test12: OK\n\n");

        printf("=> Test13: chdir\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "echo $$ > chdirtest;");
                Command_setDir(c, "/tmp/");
                Process_T p = Command_execute(c);
                assert(Process_waitFor(p) == 0);
                Process_free(&p);
                assert(File_delete("/tmp/chdirtest"));
                TRY
                {
                        Command_setDir(c, "/tmp/somenonexistingdir");
                        exit(1);
                }
                CATCH (AssertException)
                END_TRY;
                Command_free(&c);
        }
        printf("=> Test13: OK\n\n");

        printf("=> Test14: detach\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "read msg; echo \"this write will fail but should not exit the script\"; echo \"$$ still alive\" > /tmp/ondetach; exit 0;");
                onDetach(Command_execute(c));
                Command_free(&c);
        }
        printf("=> Test14: OK\n\n");

        printf("=> Test15: setuid and setgid in sub-process\n");
        {
                if (getuid() != 0) {
                        printf("\tCannot run test: not running as root\n");
                        goto skip;
                }
#ifdef DARWIN
                char *uname = "www";
#else
                char *uname = "www-data";
#endif
                struct passwd *pwd = getpwnam(uname);
                assert(pwd);
                char *script = Str_cat("if test $(id -u) -eq %d -a $(id -g) -eq %d; then exit 0; fi; exit 1;", pwd->pw_uid, pwd->pw_gid);
                Command_T c = Command_new("/bin/sh", "-c", script);
                Command_setUid(c, pwd->pw_uid);
                Command_setGid(c, pwd->pw_gid);
                Process_T p = Command_execute(c);
                assert(p);
                assert(Process_waitFor(p) == 0);
                Process_free(&p);
                Command_free(&c);
                FREE(script);
        }
skip:
        printf("=> Test15: OK\n\n");

        printf("=> Test16: set umask\n");
        {
                char *script = "tmp=\"/tmp/$$.tst\";touch $tmp;permissions="
#ifdef LINUX
                "$(stat -c '%a' $tmp);"
#elif defined(__APPLE__)
                "$(stat -f '%A' $tmp);"
#else  /* BSD systems */
                "$(stat -f '%Lp' $tmp);"
#endif
                "rm -f $tmp; if test $permissions -eq 642; then exit 0; fi; exit 1;";
                Command_T c = Command_new("/bin/sh", "-c", script);
                Command_setUmask(c, 025);
                Process_T p = Command_execute(c);
                assert(p);
                assert(Process_waitFor(p) == 0);
                Process_free(&p);
                Command_free(&c);
        }
        printf("=> Test16: OK\n\n");

        printf("============> Command Tests: OK\n\n");

}

