#include "Config.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "system/System.h"
#include "system/Time.h"
#include "Thread.h"

/**
 * System.c unity tests.
 */


static void _handler(const char *s, va_list ap) {
        assert(s);
        char buf[STRLEN];
        va_list ap_copy;
        va_copy(ap_copy, ap);
        vsnprintf(buf, sizeof(buf), s, ap);
        va_end(ap_copy);
        printf("handler: %s", buf);
        assert(Str_isEqual(buf, "\tyellow submarine (5)(6)\n"));
}


int main(void) {

        Bootstrap(); // Need to initialize library

        printf("============> Start System Tests\n\n");

        printf("=> Test0: check error description\n");
        {
                const char *error = System_getError(EINVAL);
                assert(error != NULL);
                printf("\tEINVAL description: %s\n", error);
                errno = EINVAL;
                assert(Str_isEqual(System_getLastError(), error));

        }
        printf("=> Test0: OK\n\n");

        printf("=> Test1: check filedescriptors wrapper\n");
        {
                assert(System_getDescriptorsGuarded() <= 2<<15);

        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: random data generator\n");
        {
                srandom((unsigned)(Time_now() + getpid()));
                //
                printf("\tnumber:   %llu\n", System_randomNumber());
                //
                printf("\t1  byte:  ");
                char buf0[1];
                assert(System_random(buf0, sizeof(buf0)));
                for (size_t i = 0; i < sizeof(buf0); i++) {
                        printf("%x", buf0[i]);
                }
                printf("\n");
                //
                printf("\t4  bytes: ");
                char buf1[4];
                assert(System_random(buf1, sizeof(buf1)));
                for (size_t i = 0; i < sizeof(buf1); i++) {
                        printf("%x", buf1[i]);
                }
                printf("\n");
                //
                printf("\t16 bytes: ");
                char buf2[16];
                assert(System_random(buf2, sizeof(buf2)));
                for (size_t i = 0; i < sizeof(buf2); i++) {
                        printf("%x", buf2[i]);
                }
                printf("\n");
                //
                assert(System_randomNumber() != System_randomNumber());
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: check System_error\n");
        {
                System_error("\thello %s (%d)(%ld)\n", "world", 1, 2L);
                Bootstrap_setErrorHandler(_handler);
                System_error("\tyellow %s (%d)(%ld)\n", "submarine", 5, 6L);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: check System_error\n");
        {
                Bootstrap_setAbortHandler(_handler);
                System_abort("\tyellow %s (%d)(%ld)\n", "submarine", 5, 6L);
        }
        printf("=> Test4: OK\n\n");

        printf("============> System Tests: OK\n\n");

        return 0;
}
