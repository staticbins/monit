#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "Fmt.h"


/**
 * Str.c unity tests
 */


int main(void) {

        Bootstrap(); // Need to initialize library

        printf("============> Start Ftm Tests\n\n");

        printf("=> Test1: Fmt_byte\n");
        {
                char str[10];
                Fmt_byte(0, str);
                assert(Str_isEqual(str, "0 B"));
                Fmt_byte(2048, str);
                assert(Str_isEqual(str, "2 KB"));
                Fmt_byte(2097152, str);
                assert(Str_isEqual(str, "2 MB"));
                Fmt_byte(2621440, str);
                assert(Str_isEqual(str, "2.5 MB"));
                Fmt_byte(9083741824, str);
                assert(Str_isEqual(str, "8.5 GB"));
                Fmt_byte(9083741824987653, str);
                assert(Str_isEqual(str, "8.1 PB"));
                Fmt_byte(LLONG_MAX, str);
                assert(Str_isEqual(str, "8 EB"));
                Fmt_byte(-9083741824, str);
                assert(Str_isEqual(str, "-8.5 GB"));
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: Fmt_ms\n");
        {
                char str[13];
                Fmt_ms(0, str);
                assert(Str_isEqual(str, "0 ms"));
                Fmt_ms(0.5, str);
                assert(Str_isEqual(str, "0.500 ms"));
                Fmt_ms(1, str);
                assert(Str_isEqual(str, "1 ms"));
                Fmt_ms(999.999, str);
                assert(Str_isEqual(str, "999.999 ms"));
                Fmt_ms(2000, str);
                assert(Str_isEqual(str, "2 s"));
                Fmt_ms(2123, str);
                assert(Str_isEqual(str, "2.123 s"));
                Fmt_ms(60000, str);
                assert(Str_isEqual(str, "1 m"));
                Fmt_ms(90000, str);
                assert(Str_isEqual(str, "1.500 m"));
                Fmt_ms(3600000, str);
                assert(Str_isEqual(str, "1 h"));
                Fmt_ms(1258454321, str);
                assert(Str_isEqual(str, "14.565 d"));
                Fmt_ms(3e+12, str);
                assert(Str_isEqual(str, "95.129 y"));
                Fmt_ms(-2000, str);
                assert(Str_isEqual(str, "-2 s"));
        }
        printf("=> Test2: OK\n\n");

        printf("============> Fmt Tests: OK\n\n");
        return 0;
}


