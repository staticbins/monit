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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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


static double epsilon = 1e-6;

static boolean_t _isInt(double x) {
    return fabs(x - round(x)) < epsilon;
}


/* -------------------------------------------------------- Public Methods */


char *Fmt_bytes2str(double bytes, char s[static 10]) {
    assert(s);
    static const char *kNotation[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", NULL};
    *s = 0;
    char *sign = (bytes < 0) ? "-" : "";
    bytes = fabs(bytes);
    assert(bytes < 1e+24);
    for (int i = 0; kNotation[i]; i++) {
        if (bytes >= 1024) {
            bytes /= 1024;
        } else {
            snprintf(s, 10, _isInt(bytes) ? "%s%.0lf %s" : "%s%.1lf %s", sign, bytes, kNotation[i]);
            break;
        }
    }
    return s;
}


char *Fmt_time2str(double milli, char s[static 11]) {
    assert(s);
    struct conversion {
        double base;
        char *suffix;
    } conversion[] = {
        {1000, "ms"}, // millisecond
        {60,   "s"},  // second
        {60,   "m"},  // minute
        {24,   "h"},  // hour
        {365,  "d"},  // day
        {999,  "y"}   // year
    };
    *s = 0;
    char *sign = (milli < 0) ? "-" : "";
    milli = fabs(milli);
    assert(milli < 3.14e+12); // -99.569 y
    for (int i = 0; i < (sizeof(conversion) / sizeof(conversion[0])); i++) {
        if (milli >= conversion[i].base) {
            milli /= conversion[i].base;
        } else {
            snprintf(s, 11, _isInt(milli) ? "%s%.0lf %s" : "%s%.3lf %s", sign, milli, conversion[i].suffix);
            break;
        }
    }
    return s;
}
