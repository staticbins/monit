#include "Config.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>

#include "Bootstrap.h"
#include "Str.h"
#include "system/Time.h"

/**
 * Time.c unity tests.
 */


int main(void) {

        // Note: When the below setenv() is present on Alpine linux with MUSL, the test Time_localStr test fails and returns UTC time. The tzset() is called automatically
        //       by localtime_r(). The test may fail though, if it is executed on machine, which is not in CET timezone.
        //setenv("TZ", "CET", 1);
        //tzset();

        Bootstrap(); // Need to initialize library

        printf("============> Start Time Tests\n\n");


        printf("=> Test1: check string output\n");
        {
                char result[STRLEN];
                Time_localStr(1267441200, result); /* 01 Mar 2010 12:00:00 */
                printf("\tResult: unix time 1267441200 to localtime:\n\t %s\n", result);
                assert(Str_isEqual(result, "Mon, 01 Mar 2010 12:00:00"));
                Time_str(1267441200, result); /* 01 Mar 2010 11:00:00 GMT */
                printf("\tResult: unix time 1267441200 to UTC:\n\t %s\n", result);
                assert(Str_isEqual("Mon, 01 Mar 2010 11:00:00 GMT", result));
                Time_fmt(result, STRLEN, "%D %T", 1267441200);
                printf("\tResult: 1267441200 -> %s\n", result);
                assert(Str_isEqual(result, "03/01/10 11:00:00"));
                Time_fmt(result, STRLEN, "%D %z", 1267441200);
                printf("\tResult: 1267441200 -> %s\n", result);
#ifdef AIX
                assert(Str_startsWith(result, "03/01/10 CET"));
#else
                assert(Str_startsWith(result, "03/01/10 +"));
#endif
                // Short buffer
                Time_fmt(result, 1, "%D %T", 1267441200);
                assert(Str_isEqual(result, ""));
        }
        printf("=> Test1: OK\n\n");

        printf("=> Test2: check current time\n");
        {
                struct timeval tv;
                assert(!gettimeofday(&tv, NULL));
                assert(Time_now() == tv.tv_sec);
        }
        printf("=> Test2: OK\n\n");

        printf("=> Test3: sleep 0.1s\n");
        {
                long long startMs = Time_monotonic().milliseconds;
                Time_usleep(100000LL); // Sleep for 100 ms (100,000 µs)
                long long elapsedMs = Time_monotonic().milliseconds - startMs;
                printf("\tElapsed ms: %lld\n", elapsedMs);
                long long toleranceMs = 10LL; // Tolerate 10 ms drift
                assert(elapsedMs >= 100 && elapsedMs <= 100 + toleranceMs);
        }
        printf("=> Test3: OK\n\n");

        printf("=> Test4: uptime\n");
        {
                time_t days = 668040;
                time_t hours = 63240;
                time_t min = 2040;
                char result[24];
                printf("\tResult: uptime days: %s\n", Time_uptime(days, result));
                assert(Str_isEqual(result, "7d, 17h, 34m"));
                printf("\tResult: uptime hours: %s\n", Time_uptime(hours, result));
                assert(Str_isEqual(result, "17h, 34m"));
                printf("\tResult: uptime min: %s\n", Time_uptime(min, result));
                assert(Str_isEqual(result, "34m"));
                printf("\tResult: uptime 0: %s\n", Time_uptime(0, result));
                assert(Str_isEqual(result, ""));
        }
        printf("=> Test4: OK\n\n");

        printf("=> Test5: Time attributes\n");
        {
                char b[STRLEN];
                time_t time = 730337459; // Sun, 21 Feb 1993 23:30:59 GMT
                printf("\tResult: %s (winter time)\n", Time_str(time, b));
                assert(Str_isEqual(b, "Sun, 21 Feb 1993 23:30:59 GMT"));
                time = 1253045894; // Tue, 15 Sep 2009n 20:18:14
                printf("\tResult: %s (DTS/summer time)\n", Time_str(time, b));
                assert(Str_startsWith(b, "Tue, 15 Sep 2009 20:18:14"));
        }
        printf("=> Test5: OK\n\n");

        printf("=> Test6: Time_build\n");
        {
                time_t time = Time_build(2001, 1, 29, 12, 0, 0);
                struct tm tm; gmtime_r(&time, &tm);
                assert(tm.tm_sec == 0);
                assert(tm.tm_min == 0);
                assert(tm.tm_hour == 12);
                assert(tm.tm_mday == 29);
                assert(tm.tm_mon + 1 == 1);
                assert(tm.tm_year + 1900 == 2001);
                // Verify assert on out of range
                TRY
                {
                        Time_build(1969, 1, 29, 12, 0, 0);
                        printf("Test failed\n");
                        exit(1);
                }
                CATCH (AssertException)
                END_TRY;
                TRY
                {
                        Time_build(1970, 0, 29, 12, 0, 0);
                        printf("Test failed\n");
                        exit(1);
                }
                CATCH (AssertException)
                END_TRY;
        }
        printf("=> Test6: OK\n\n");

        printf("=> Test7: Time_incron\n");
        {
                // Cannot test match on time as the TZ this test
                // runs in is unknown. Time_incron converts time
                // to local time.

                // const char *exactmatch = "27 11 5 7 2";
                const char *matchall = "* * * * *";
                const char *invalid1 = "a bc d";
                const char *invalid2 = "* * * *  "; // Too few fields
                const char *invalid3 = "* * * * * * "; // Too many fields
                // const char *range1 = "* 10-11 1-5 * 1-5";
                // const char *rangeoutside = "1-10 9-10 1-5 * 1-5";
                // const char *sequence = "* 10,11 1-3,5,6 * *";
                // const char *sequenceoutside = "* 10,11,12 4,5,6 * 0,6";
                time_t time = Time_build(2011, 7, 5, 11, 27, 5);
                // assert(Time_incron(exactmatch, time));
                assert(Time_incron(matchall, time));
                assert(! Time_incron(invalid1, time));
                assert(! Time_incron(invalid2, time));
                assert(! Time_incron(invalid3, time));
                // assert(Time_incron(range1, time));
                // assert(! Time_incron(rangeoutside, time));
                // assert(Time_incron(sequence, time));
                //assert(! Time_incron(sequenceoutside, time));
        }
        printf("=> Test7: OK\n\n");

        printf("=> Test8: Time_toDateTime\n");
        {
#if HAVE_STRUCT_TM_TM_GMTOFF
#define TM_GMTOFF tm_gmtoff
#else
#define TM_GMTOFF tm_wday
#endif
                struct tm t;
                // DateTime ISO-8601 format
                assert(Time_toDateTime("2013-12-14T09:38:08Z", &t));
                assert(t.tm_year == 2013);
                assert(t.tm_mon  == 11);
                assert(t.tm_mday == 14);
                assert(t.tm_hour == 9);
                assert(t.tm_min  == 38);
                assert(t.tm_sec  == 8);
                // Date
                assert(Time_toDateTime("2013-12-14", &t));
                assert(t.tm_year == 2013);
                assert(t.tm_mon  == 11);
                assert(t.tm_mday == 14);
                // Date dd/mm/yyyy
                assert(Time_toDateTime("14/12/2013", &t));
                assert(t.tm_year == 2013);
                assert(t.tm_mon  == 11);
                assert(t.tm_mday == 14);
                // Time
                assert(Time_toDateTime("09:38:08", &t));
                assert(t.tm_hour == 9);
                assert(t.tm_min  == 38);
                assert(t.tm_sec  == 8);
                // Compressed DateTime
                assert(Time_toDateTime(" 20131214093808", &t));
                assert(t.tm_year == 2013);
                assert(t.tm_mon  == 11);
                assert(t.tm_mday == 14);
                assert(t.tm_hour == 9);
                assert(t.tm_min  == 38);
                assert(t.tm_sec  == 8);
                // Compressed Date
                assert(Time_toDateTime(" 20131214 ", &t));
                assert(t.tm_year == 2013);
                assert(t.tm_mon  == 11);
                assert(t.tm_mday == 14);
                // Compressed Time
                assert(Time_toDateTime("093808", &t));
                assert(t.tm_hour == 9);
                assert(t.tm_min  == 38);
                assert(t.tm_sec  == 8);
                // Time: HH:MM
                assert(Time_toDateTime("09:38", &t));
                assert(t.tm_hour == 9);
                assert(t.tm_min  == 38);
                assert(t.tm_sec  == 0);
                // Reverse DateTime
                assert(Time_toDateTime(" 09:38:08 2013-12-14", &t));
                assert(t.tm_year == 2013);
                assert(t.tm_mon  == 11);
                assert(t.tm_mday == 14);
                assert(t.tm_hour == 9);
                assert(t.tm_min  == 38);
                assert(t.tm_sec  == 8);
                // DateTime with timezone Zulu (UTC)
                assert(Time_toDateTime("The Battle of Stamford Bridge 1066-09-25 12:15:33+00:00", &t));
                assert(t.tm_year == 1066);
                assert(t.tm_mon  == 8);
                assert(t.tm_mday == 25);
                assert(t.tm_hour == 12);
                assert(t.tm_min  == 15);
                assert(t.tm_sec  == 33);
                assert(t.TM_GMTOFF == 0); // offset from UTC in seconds
                // Time with timezone
                assert(Time_toDateTime(" 09:38:08+01:45", &t));
                assert(t.tm_hour == 9);
                assert(t.tm_min  == 38);
                assert(t.tm_sec  == 8);
                assert(t.TM_GMTOFF == 6300);
                // Time with timezone PST compressed
                assert(Time_toDateTime("Pacific Time Zone 09:38:08 -0800 ", &t));
                assert(t.tm_hour == 9);
                assert(t.tm_min  == 38);
                assert(t.tm_sec  == 8);
                assert(t.TM_GMTOFF == -28800);
                // Date without time, tz should not be set
                assert(Time_toDateTime("2013-12-15-0800 ", &t));
                assert(t.TM_GMTOFF == 0);
                // RFC 7231 IMF-fixdate (HTTP date)
                assert(Time_toDateTime("Sun, 06 Nov 1994 08:49:37 GMT", &t));
                assert(t.tm_year == 1994);
                assert(t.tm_mon  == 10);
                assert(t.tm_mday == 6);
                assert(t.tm_hour == 8);
                assert(t.tm_min  == 49);
                assert(t.tm_sec  == 37);
                // Invalid date
                TRY {
                        Time_toDateTime("1901-13-25", &t);
                        printf("\t Test Failed\n");
                        exit(1);
                } CATCH (AssertException) {
                        // OK
                } ELSE {
                        printf("\t Test Failed with wrong exception\n");
                        exit(1);
                }
                END_TRY;
                TRY {
                        Time_toDateTime("19", &t);
                        printf("\t Test Failed\n");
                        exit(1);
                } CATCH (AssertException) {
                        // OK
                } ELSE {
                        printf("\t Test Failed with wrong exception\n");
                        exit(1);
                }
                END_TRY;
                TRY {
                        Time_toDateTime("", &t);
                        printf("\t Test Failed\n");
                        exit(1);
                } CATCH (AssertException) {
                        // OK
                } ELSE {
                        printf("\t Test Failed with wrong exception\n");
                        exit(1);
                }
                END_TRY;
        }
        printf("=> Test8: OK\n\n");

        printf("=> Test9: Time_toTimestamp\n");
        {
                // Time, fraction of second is ignored. No timezone in string means UTC
                time_t t = Time_toTimestamp("2013-12-15 00:12:58.123456");
                assert(t == 1387066378);
                // TimeZone east
                t = Time_toTimestamp("Tokyo timezone: 2013-12-15 09:12:58+09:00");
                assert(t == 1387066378);
                // TimeZone west
                t = Time_toTimestamp("New York timezone: 2013-12-14 19:12:58-05:00");
                assert(t == 1387066378);
                // TimeZone east with hour and minute offset
                t = Time_toTimestamp("Nepal timezone: 2013-12-15 05:57:58+05:45");
                assert(t == 1387066378);
                // TimeZone Zulu
                t = Time_toTimestamp("Grenwich timezone: 2013-12-15 00:12:58Z");
                assert(t == 1387066378);
                // Compressed
                t = Time_toTimestamp("20131214191258-0500");
                assert(t == 1387066378);
                // RFC 7231 IMF-fixdate (HTTP date)
                t = Time_toTimestamp("Sun, 15 Dec 2013 00:12:58 GMT");
                assert(t == 1387066378);
                // Invalid timestamp string
                TRY {
                        Time_toTimestamp("2013-13-15 25:12:58");
                        // Should not come here
                        printf("\t Test Failed\n");
                        exit(1);
                } CATCH (AssertException) {
                        // OK
                } ELSE {
                        printf("\t Test Failed with wrong exception\n");
                        exit(1);
                }
                END_TRY;
                // NULL
                assert(Time_toTimestamp("") == 0);
                assert(Time_toTimestamp(NULL) == 0);
        }
        printf("=> Test9: OK\n\n");

        printf("=> Test10: Time_milli\n");
        {
                long long t1 = Time_milli();
                usleep(500000);
                long long t2 = Time_milli();
                assert(t2 - t1 >= 500LL);
        }
        printf("=> Test10: OK\n\n");

        printf("=> Test11: Time_micro\n");
        {
                long long t1 = Time_micro();
                usleep(500);
                long long t2 = Time_micro();
                assert(t2 - t1 >= 500LL);
        }
        printf("=> Test11: OK\n\n");

        printf("============> Time Tests: OK\n\n");

        return 0;
}


