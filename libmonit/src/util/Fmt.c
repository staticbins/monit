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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
#include <math.h>

#include "Fmt.h"


/* ----------------------------------------------------------- Definitions */


static double epsilon = 1e-5;

static bool _isInt(double x) {
        return fabs(x - round(x)) < epsilon;
}

// Maximum number of time units (ms -> year)
#define FMT_TIME_UNITS 6

// Maximum value that can be represented (-99.569 y)
#define FMT_TIME_MAX 3.14e+12

static const struct time_unit {
        double base;
        const char* suffix;
} time_units[FMT_TIME_UNITS] = {
        {1000, "ms"},
        {60,   "s"},
        {60,   "m"},
        {24,   "h"},
        {365,  "d"},
        {100,  "y"} // current max ~99.569 years
};

// Maximum number of bytes units (B -> ZB)
#define FMT_BYTES_UNITS 8

// Maximum value that can be represented (ZB - 1)
#define FMT_BYTES_MAX 1e+24

static const struct byte_unit {
        const char* suffix;
        const double factor;  // For validation
} byte_units[FMT_BYTES_UNITS] = {
        {"B",  1},
        {"kB", 1e3},
        {"MB", 1e6},
        {"GB", 1e9},
        {"TB", 1e12},
        {"PB", 1e15},
        {"EB", 1e18},
        {"ZB", 1e21}
};


/* -------------------------------------------------------- Public Methods */


char* Fmt_bytes2str(double bytes, char s[static FMT_BYTES_BUFSIZE]) {
        assert(s);
        *s = 0;
        if (isnan(bytes)) {
                snprintf(s, FMT_BYTES_BUFSIZE, "NaN");
                return s;
        }
        if (isinf(bytes)) {
                snprintf(s, FMT_BYTES_BUFSIZE, bytes > 0 ? "Inf" : "-Inf");
                return s;
        }
        const char* sign = (bytes < 0) ? "-" : "";
        bytes = fabs(bytes);
        assert(bytes < FMT_BYTES_MAX);
        if (fabs(bytes) < epsilon) {
                snprintf(s, FMT_BYTES_BUFSIZE, "0 B");
                return s;
        }
        // Find and set appropriate unit
        size_t unit;
        for (unit = 0; unit < FMT_BYTES_UNITS; unit++) {
                if (bytes >= 1024) {
                        bytes /= 1024;
                } else {
                        break;
                }
        }
        snprintf(s, FMT_BYTES_BUFSIZE,
                 _isInt(bytes) ? "%s%.0lf %s" : "%s%.1lf %s",
                 sign, bytes, byte_units[unit].suffix);
        return s;
}


char* Fmt_time2str(double milli, char s[static FMT_TIME_BUFSIZE]) {
        assert(s);
        *s = 0;
        // Handle special cases
        if (isnan(milli)) {
                snprintf(s, FMT_TIME_BUFSIZE, "NaN");
                return s;
        }
        if (isinf(milli)) {
                snprintf(s, FMT_TIME_BUFSIZE, milli > 0 ? "Inf" : "-Inf");
                return s;
        }
        const char* sign = (milli < 0) ? "-" : "";
        milli = fabs(milli);
        assert(milli < FMT_TIME_MAX);
        if (fabs(milli) < epsilon) {
                snprintf(s, FMT_TIME_BUFSIZE, "0 ms");
                return s;
        }
        // Find and set appropriate unit
        size_t unit;
        for (unit = 0; unit < FMT_TIME_UNITS; unit++) {
                if (milli >= time_units[unit].base) {
                        milli /= time_units[unit].base;
                } else {
                        break;
                }
        }
        snprintf(s, FMT_TIME_BUFSIZE,
                 _isInt(milli) ? "%s%.0lf %s" : "%s%.3lf %s",
                 sign, milli, time_units[unit].suffix);
        return s;
}
