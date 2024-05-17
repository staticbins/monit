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
#include "system/Random.h"
#include "system/Time.h"

/**
 * Ranom.c unity tests.
 */


int main(void) {

        Bootstrap(); // Need to initialize library

        printf("============> Start Random Tests\n\n");

        printf("=> Test0: Random data generator\n");
        {
                //
                printf("\tnumber:   %llu\n", Random_number());
                //
                printf("\t1  byte:  ");
                char buf0[1];
                assert(Random_bytes(buf0, sizeof(buf0)));
                for (size_t i = 0; i < sizeof(buf0); i++) {
                        printf("%x", buf0[i]);
                }
                printf("\n");
                //
                printf("\t4  bytes: ");
                char buf1[4];
                assert(Random_bytes(buf1, sizeof(buf1)));
                for (size_t i = 0; i < sizeof(buf1); i++) {
                        printf("%x", buf1[i]);
                }
                printf("\n");
                //
                printf("\t16 bytes: ");
                char buf2[16];
                assert(Random_bytes(buf2, sizeof(buf2)));
                for (size_t i = 0; i < sizeof(buf2); i++) {
                        printf("%x", buf2[i]);
                }
                printf("\n");
                //
                assert(Random_number() != Random_number());
        }
        printf("=> Test0: OK\n\n");

        printf("============> Random Tests: OK\n\n");

        return 0;
}
