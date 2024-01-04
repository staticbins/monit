#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>

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


bool timeout_called = false;

static void onExec(Process_T P) {
        assert(P);
        char buf[STRLEN];
        // Child process info
        printf("\tSubprocess ((pid=%d, uid=%d, gid=%d) created with cwd (%s)\n", Process_getPid(P), Process_getUid(P), Process_getGid(P), Process_getDir(P));
        InputStream_T in = Process_getInputStream(P);
        OutputStream_T out = Process_getOutputStream(P);
        InputStream_T err = Process_getErrorStream(P);
        printf("\tSub-Process is %s\n", Process_isRunning(P) ? "running" : "not running");
        printf("\tCommunication with child:\n");
        if (! InputStream_readLine(in, buf, STRLEN)) {
                InputStream_readLine(err, buf, STRLEN);
                printf("\tError in script: %s\n", buf);
        } else {
                printf("\t%s", buf);
                OutputStream_print(out, "Elessar Telcontar\n");
                assert(OutputStream_flush(out) > 0);
                char *line = InputStream_readLine(in, buf, STRLEN);
                assert(line);
                printf("\t%s", line);
        }
        printf("Process exited with status: %d\n", Process_waitFor(P));
        Process_free(&P);
        assert(! P);
}


static void onTerminate(Process_T P) {
        assert(P);
        printf("\tTest terminate subprocess ((pid=%d)\n", Process_getPid(P));
        assert(Process_isRunning(P));
        Process_terminate(P);
        printf("\tWaiting on process to terminate.. ");
        fflush(stdout);
        printf("Process exited with status: %d\n", Process_waitFor(P));
        Process_free(&P);
        assert(! P);
}


static void onKill(Process_T P) {
        assert(P);
        printf("\tTest kill subprocess ((pid=%d)\n", Process_getPid(P));
        assert(Process_isRunning(P));
        Process_kill(P);
        printf("\tWaiting on process to exit.. ");
        printf("Process exited with status: %d\n", Process_waitFor(P));
        Process_free(&P);
        assert(! P);
}


static void onEnv(Process_T P) {
        assert(P);
        char buf[STRLEN];
        InputStream_T in = Process_getInputStream(P);
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
        assert(Process_getInputStream(P) == NULL);
        // Assert that the script exited cleanly
        assert(Process_waitFor(P) == 0);
        Process_free(&P);
        // Finally assert that the script did continue and wrote this file
        assert(File_delete("/tmp/ondetach"));
        assert(! P);
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

        printf("=> Test2: set and get uid/gid/umask\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "ps -aef|grep monit");
                assert(c);
                // Check that default is 0
                assert(Command_getUid(c) == 0);
                assert(Command_getGid(c) == 0);
                // set and test uid and gid
                Command_setUid(c,42);
                assert(Command_getUid(c) == 42);
                Command_setGid(c,148);
                assert(Command_getGid(c) == 148);
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test4: set and get env\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "ps -aef|grep monit");
                assert(c);
                // Set and get env string
                Command_setEnv(c, "PATH", "/usr/bin");
                Command_setEnv(c, "SHELL", "/bin/bash");
                Command_setEnv(c, "PAT", "Carroll");
                assert(Str_isEqual(Command_getEnv(c, "PATH"), "/usr/bin"));
                assert(Str_isEqual(Command_getEnv(c, "SHELL"), "/bin/bash"));
                assert(Str_isEqual(Command_getEnv(c, "PAT"), "Carroll"));
                // Empty and NULL value
                Command_setEnv(c, "PATH", "");
                Command_setEnv(c, "SHELL", NULL);
                assert(Str_isEqual(Command_getEnv(c, "PATH"), ""));
                assert(Str_isEqual(Command_getEnv(c, "SHELL"), ""));
                // Unknown variable should result in NULL
                assert(Command_getEnv(c, "UKNOWNVARIABLE") == NULL);
                // vSetEnv
                Command_vSetEnv(c, "PID", "%ld", (long)getpid());
                assert(Str_parseLLong(Command_getEnv(c, "PID")) > 1);
                Command_vSetEnv(c, "ZERO", NULL);
                assert(Str_isEqual(Command_getEnv(c, "ZERO"), ""));
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: set and get Command\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "ps -aef|grep monit");
                assert(c);
                List_T l = Command_getCommand(c);
                assert(Str_isEqual(l->head->e, "/bin/sh"));
                assert(Str_isEqual(l->head->next->e, "-c"));
                assert(Str_isEqual(l->head->next->next->e, "ps -aef|grep monit"));
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test5: OK\n\n");
        
        printf("=> Test6: Append arguments\n");
        {
                Command_T c = Command_new("/bin/ls");
                assert(c);
                Command_appendArgument(c, "-l");
                Command_appendArgument(c, "-t");
                Command_appendArgument(c, "-r");
                List_T l = Command_getCommand(c);
                assert(Str_isEqual(l->head->e, "/bin/ls"));
                assert(Str_isEqual(l->head->next->e, "-l"));
                assert(Str_isEqual(l->head->next->next->e, "-t"));
                assert(Str_isEqual(l->head->next->next->next->e, "-r"));
                assert(l->head->next->next->next->next == NULL);
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test6: OK\n\n");
        
        printf("=> Test7: execute invalid program\n");
        {
                // Program producing error
                Command_T c = Command_new("/bin/sh", "-c", "not_a_program;");
                assert(c);
                Command_setDir(c, "/");
                printf("\tThis should produce an error:\n");
                onExec(Command_execute(c));
                Command_free(&c);
                assert(!c);
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
                assert(c);
                Process_T p = Command_execute(c);
                if (p)
                        onExec(p);
                else
                        ERROR("Command_execute error: %s\n", System_getLastError());
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test8: OK\n\n");

        printf("=> Test9: terminate sub-process\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "exec sleep 30;");
                assert(c);
                onTerminate(Command_execute(c));
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test9: OK\n\n");

        printf("=> Test10: kill sub-process\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "trap 1 2 15; sleep 30; ");
                assert(c);
                onKill(Command_execute(c));
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test10: OK\n\n");
        
        printf("=> Test11: environment in sub-process\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "echo $SULT");
                assert(c);
                // Set environment in sub-process only
                Command_setEnv(c, "SULT", "Ylajali");
                onEnv(Command_execute(c));
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test11: OK\n\n");
        
        printf("=> Test12: on execute error\n");
        {
                // Executing a directory should produce an execve error
                Command_T c = Command_new("/tmp");
                assert(c);
                Process_T p = Command_execute(c);
                assert(! p);
                Command_free(&c);
                printf("\tOK, got execute error -- %s\n", System_getLastError());
                assert(!c);
        }
        printf("=> Test12: OK\n\n");

        printf("=> Test13: chdir\n");
        {
                Command_T c = Command_new("/bin/sh", "-c", "echo $$ > chdirtest;");
                assert(c);
                Command_setDir(c, "/tmp/");
                Process_T p = Command_execute(c);
                assert(p);
                assert(Process_waitFor(p) == 0);
                Process_free(&p);
                assert(File_delete("/tmp/chdirtest"));
                TRY
                {
                        Command_setDir(c, "/tmp/somenonexistingdir");
                        printf("Setting invalid work dir failed\n");
                        exit(1);
                }
                ELSE
                END_TRY;
                Command_free(&c);
                printf("\tOK, got execute error -- %s\n", System_getLastError());
                assert(!c);
        }
        printf("=> Test13: OK\n\n");

        printf("=> Test14: on execve(2) error\n");
        {
                // Executing a directory should produce an exec error
                Command_T c = Command_new("/tmp");
                assert(c);
                Process_T p = Command_execute(c);
                assert(! p);
                Command_free(&c);
                printf("\tOK, got execute error -- %s\n", System_getLastError());
                assert(!c);
        }
        printf("=> Test14: OK\n\n");

        printf("=> Test15: detach\n");
        {
                /* Test explained: The script will block on read waiting for input.
                 Instead we detach (close pipes) in onDetach which will cause read
                 to return immediately with eof (because of broken pipe). The write
                 to stdout will fail, but it should not kill the script with SIGPIPE
                 as Command ensure the process ignore this signal. Instead the script
                 should exit cleanly with 0 after writing to a file to verify it ran.
                 */
                Command_T c = Command_new("/bin/sh", "-c", "read msg; echo \"write will fail but should not exit the script\"; echo \"$$ still alive\" > /tmp/ondetach; exit 0;");
                assert(c);
                onDetach(Command_execute(c));
                Command_free(&c);
                assert(!c);
        }
        printf("=> Test15: OK\n\n");

        printf("============> Command Tests: OK\n\n");

        return 0;
}

