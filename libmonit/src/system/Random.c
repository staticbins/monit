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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif

#include "io/File.h"
#include "system/Time.h"
#include "system/Random.h"


/**
 * Implementation of the Random Facade for Unix Systems.
 *
 * @author https://tildeslash.com
 * @see https://mmonit.com
 * @file
 */


/* ----------------------------------------------------------- Definitions */


#if ! defined HAVE_ARC4RANDOM_BUF
static pthread_once_t once_control = PTHREAD_ONCE_INIT;
#endif


/* --------------------------------------------------------------- Private */


#if ! defined HAVE_ARC4RANDOM_BUF
static void _seed_once(void) { srandom((unsigned)(Time_now() + getpid())); }
#endif


/* ---------------------------------------------------------------- Public */


bool Random_bytes(void *buf, size_t nbytes) {
#ifdef HAVE_ARC4RANDOM_BUF
        arc4random_buf(buf, nbytes);
        return true; // arc4random_buf doesn't fail
#else
        pthread_once(&once_control, _seed_once);
#ifdef HAVE_GETRANDOM
        return (getrandom(buf, nbytes, 0) == (ssize_t)nbytes);
#else
        int fd = File_open("/dev/urandom", "r");
        if (fd >= 0) {
                ssize_t bytes = read(fd, buf, nbytes);
                close(fd);
                return (bytes >= 0 && (size_t)bytes == nbytes);
        }
        // Fallback to random()
        char *_buf = buf;
        for (size_t i = 0; i < nbytes; i++) {
                _buf[i] = random() % 256;
        }
        return true;
#endif
#endif
}


unsigned long long Random_number(void) {
        unsigned long long random;
        Random_bytes(&random, sizeof(random));
        return random;
}

