#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>

#include "Bootstrap.h"
#include "Str.h"
#include "Convert.h"


/**
 * Str.c unity tests
 */


int main(void) {

        Bootstrap(); // Need to initialize library

        printf("============> Start Convert Tests\n\n");

        printf("=> Test1: Convert_bytes2str\n");
        {
                char str[10];
                Convert_bytes2str(0, str);
                assert(Str_isEqual(str, "0 B"));
                Convert_bytes2str(2048, str);
                assert(Str_isEqual(str, "2 KB"));
                Convert_bytes2str(2097152, str);
                assert(Str_isEqual(str, "2 MB"));
                Convert_bytes2str(2621440, str);
                assert(Str_isEqual(str, "2.5 MB"));
                Convert_bytes2str(9083741824, str);
                assert(Str_isEqual(str, "8.5 GB"));
                Convert_bytes2str((double)9083741824987653, str);
                assert(Str_isEqual(str, "8.1 PB"));
                Convert_bytes2str((double)LLONG_MAX, str);
                assert(Str_isEqual(str, "8 EB"));
                Convert_bytes2str(-9083741824, str);
                assert(Str_isEqual(str, "-8.5 GB"));
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: Convert_time2str\n");
        {
                char str[13];
                Convert_time2str(0, str);
                assert(Str_isEqual(str, "0 ms"));
                Convert_time2str(0.5, str);
                assert(Str_isEqual(str, "0.500 ms"));
                Convert_time2str(1, str);
                assert(Str_isEqual(str, "1 ms"));
                Convert_time2str(999.999, str);
                assert(Str_isEqual(str, "999.999 ms"));
                Convert_time2str(2000, str);
                assert(Str_isEqual(str, "2 s"));
                Convert_time2str(2123, str);
                assert(Str_isEqual(str, "2.123 s"));
                Convert_time2str(60000, str);
                assert(Str_isEqual(str, "1 m"));
                Convert_time2str(90000, str);
                assert(Str_isEqual(str, "1.500 m"));
                Convert_time2str(3600000, str);
                assert(Str_isEqual(str, "1 h"));
                Convert_time2str(1258454321, str);
                assert(Str_isEqual(str, "14.565 d"));
                Convert_time2str(3e+12, str);
                assert(Str_isEqual(str, "95.129 y"));
                Convert_time2str(-2000, str);
                assert(Str_isEqual(str, "-2 s"));
        }
        printf("=> Test2: OK\n\n");

        printf("============> Convert Tests: OK\n\n");
        return 0;
}


