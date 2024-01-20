#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "Array.h"

/**
 * Array.c unit tests.
 */


typedef struct value_t {
        int key;
        char value[STRLEN];
} *value_t;


static void _apply(int key, void **value, void *ap) {
        *(int *)ap += 1;
        value_t v = *value;
        assert(key == v->key);
        assert(Str_parseInt(v->value) == key);
}

static bool _predicate(void *value, void *needle) {
        value_t v = value;
        int term = *(int*)needle;
        return v->key == term;
}

static void _release(__attribute__ ((unused))int key, void **value, void *ap) {
        *(int *)ap -= 1;
        FREE(*value);
}


int main(void) {
        Array_T T = NULL;

        Bootstrap(); // Need to initialize library

        printf("============> Start Array Tests\n\n");

        printf("=> Test0: create\n");
        {
                T = Array_new(1024);
                assert(T);
                assert(Array_length(T) == 0);
        }
        printf("=> Test0: OK\n\n");

        printf("=> Test1: Array_put() & Array_length()\n");
        {
                for (int i = 0; i < 20; i++) {
                        value_t v = ALLOC(sizeof *(v));
                        v->key = i;
                        snprintf(v->value, STRLEN, "%d", i);
                        assert(Array_put(T, i, v) == NULL); // Check that the entry was not present already
                        assert(Array_put(T, i, v) != NULL); // Try to put duplicate
                }
                assert(Array_length(T) == 20);
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: Array_get()\n");
        {
                assert(Array_get(T, 20) == NULL);
                assert(Array_get(T, 10));
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: Array_remove()\n");
        {
                value_t save;
                assert((save = Array_remove(T, 10)));
                assert(save->key == 10);
                assert(Array_get(T, 10) == NULL);
                assert(Array_length(T) == 19);
                // Put it back for reuse below
                Array_put(T, 10, save);
                assert(Array_get(T, 10));
                assert(Array_length(T) == 20);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: Array_map()\n");
        {
                int i = 0;
                Array_map(T, _apply, &i);
                assert(i == 20);
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: Array_find()\n");
        {
                int needle = 12;
                value_t v = Array_find(T, _predicate, &needle);
                assert(v);
                assert(v->key == needle);
                needle = 123;
                v = Array_find(T, _predicate, &needle);
                assert(v == NULL);
        }
        printf("=> Test5: OK\n\n");

       printf("=> Test6: Array_free\n");
        {
                int i = Array_length(T);
                assert(i == 20);
                Array_map(T, _release, &i);
                assert(i == 0);
                assert(Array_length(T) == 20);
                Array_free(&T);
                assert(T == NULL);
        }
        printf("=> Test6: OK\n\n");
        
        printf("=> Test7: sparseness()\n");
        {
                T = Array_new(4);
                int numbers[] = {0, 509, 1021, 2053, 4093, 8191, 16381, 32771, 65521, -INT_MAX, INT_MAX};
                int numbers_length = (int)(sizeof(numbers)/sizeof(numbers[0]));
                for (int i = 0; i < numbers_length; i++)
                        assert(Array_put(T, numbers[i], &numbers[i]) == NULL);
                assert(Array_length(T) == numbers_length);
                for (int i = 0; i < numbers_length; i++) {
                        int *n = Array_get(T, numbers[i]);
                        assert(*n == numbers[i]);
                }
                Array_free(&T);
        }
        printf("=> Test7: OK\n\n");

        printf("============> Array Tests: OK\n\n");
}

