#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "Dispatcher.h"
#include "Thread.h"
#include "system/Time.h"

/**
 * Dispatcher.c unity tests.
 */


static void _process(void *args) {
        const char *s = args;
        printf("\tthread ID %lu processing request %s\n", (unsigned long)Thread_self(), s);
        assert(Str_member(s, (const char*[]){"1", "2", "3", 0}));
        Time_usleep(50);
        return;
}


int main(void) {
        Bootstrap(); // Need to initialize library

        printf("============> Start Dispatcher Tests\n\n");

        printf("=> Test0: create/destroy\n");
        {
                Dispatcher_T dispatcher = Dispatcher_new(5, 30, _process);
                assert(dispatcher);
                Dispatcher_free(&dispatcher);
                assert(dispatcher == NULL);
        }
        printf("=> Test0: OK\n\n");

        printf("=> Test1: add three requests to the queue\n");
        {
                Dispatcher_T dispatcher = Dispatcher_new(5, 30, _process);
                assert(dispatcher);
                assert(Dispatcher_add(dispatcher, "1") == true);
                assert(Dispatcher_add(dispatcher, "2") == true);
                assert(Dispatcher_add(dispatcher, "3") == true);
                Dispatcher_free(&dispatcher);
                assert(dispatcher == NULL);
        }
        printf("=> Test1: OK\n\n");

        printf("============> Dispatcher Tests: OK\n\n");

        return 0;
}
