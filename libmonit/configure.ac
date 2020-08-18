# Copyright (C) Tildeslash Ltd. All rights reserved.

AC_PREREQ([2.53])

AC_INIT([libmonit], [1.0], [monit-dev@tildeslash.com])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src])

# ---------------------------------------------------------------------------
# Programs 
# ---------------------------------------------------------------------------

AC_PROG_CC

AX_CHECK_COMPILE_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"])
if test `uname` != "AIX"; then
        AX_CHECK_COMPILE_FLAG([-fstack-protector-all], [CFLAGS="$CFLAGS -fstack-protector-all"])
        AX_CHECK_COMPILE_FLAG([-fcf-protection=full], [CFLAGS="$CFLAGS -fcf-protection=full"])
        AX_CHECK_COMPILE_FLAG([-fstack-clash-protection], [CFLAGS="$CFLAGS -fstack-clash-protection"])
fi

# ---------------------------------------------------------------------------
# Libtool 
# ---------------------------------------------------------------------------

LT_INIT

# ------------------------------------------------------------------------
# AddressSanitizer
# ------------------------------------------------------------------------

AC_MSG_CHECKING([for AddressSanitizer support])
AC_ARG_WITH(asan,
    [  --with-asan             enable the use of AddressSanitizer (default: disabled)],
    [
        dnl Check the withvalue
        if test "x$withval" = "xno" ; then
            use_asan=0
            AC_MSG_RESULT([disabled])
        fi
        if test "x$withval" = "xyes" ; then
            use_asan=1
            AC_MSG_RESULT([enabled])
        fi
    ],
    [
        use_asan=0
        AC_MSG_RESULT([disabled])
    ]
)

if test "$use_asan" = "1"; then
        AX_CHECK_COMPILE_FLAG([-fsanitize=address], [CFLAGS="$CFLAGS -fsanitize=address"])
        AX_CHECK_COMPILE_FLAG([-fno-omit-frame-pointer], [CFLAGS="$CFLAGS -fno-omit-frame-pointer"])
        AX_CHECK_COMPILE_FLAG([-fsanitize=bool], [CFLAGS="$CFLAGS -fsanitize=bool"])
        AX_CHECK_COMPILE_FLAG([-fsanitize=enum], [CFLAGS="$CFLAGS -fsanitize=enum"])
        AX_CHECK_COMPILE_FLAG([-fsanitize=float-divide-by-zero], [CFLAGS="$CFLAGS -fsanitize=float-divide-by-zero"])
        AX_CHECK_COMPILE_FLAG([-fsanitize-address-use-after-scope], [CFLAGS="$CFLAGS -fsanitize-address-use-after-scope"])
        AX_CHECK_COMPILE_FLAG([-fsanitize=signed-integer-overflow], [CFLAGS="$CFLAGS -fsanitize=signed-integer-overflow"])
        AX_CHECK_COMPILE_FLAG([-fsanitize=vla-bound], [CFLAGS="$CFLAGS -fsanitize=vla-bound"])
        AX_CHECK_COMPILE_FLAG([-fsanitize=bounds-strict], [CFLAGS="$CFLAGS -fsanitize=bounds-strict"])
        AX_CHECK_COMPILE_FLAG([-fsanitize=null], [CFLAGS="$CFLAGS -fsanitize=null "])
        AX_CHECK_COMPILE_FLAG([-fsanitize=object-size], [CFLAGS="$CFLAGS -fsanitize=object-size"])
fi

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------

UNIT_TEST="test"
AC_ARG_ENABLE(optimized,
	AS_HELP_STRING([--enable-optimized], 
        	[Build software optimized. Unit Tests are not enabled with this option]),
    [
        if test "x$enableval" = "xyes" ; then
   	    	CFLAGS=`echo $CFLAGS|sed 's/-g[[^ ]]*//g'`
                CFLAGS=`echo $CFLAGS|sed 's/-O.//g'`
		CFLAGS="$CFLAGS -O3 -DNDEBUG"
		OPTIMIZED=1
                UNIT_TEST=""
	else
		OPTIMIZED=0
        fi
    ],
    [
	OPTIMIZED=0
    ]
)

AC_SUBST(UNIT_TEST)

AC_ARG_ENABLE(profiling,
        AS_HELP_STRING([--enable-profiling],
                [Build with debug and profiling options]),
    [
        if test "x$enableval" = "xyes" ; then
   	    	CFLAGS=`echo $CFLAGS|sed 's/-g.//g'`
                CFLAGS=`echo $CFLAGS|sed 's/-O.//g'`
                CFLAGS="$CFLAGS -g -pg -fprofile-arcs -ftest-coverage"
                profile="true"
        fi
    ],
    [
        profile="false"
    ]
)

AC_ARG_WITH([zlib],
        AS_HELP_STRING([--with-zlib(=<path>)],
                [Link Monit with zlib. An optional path argument may
                be given to specify the top-level directory to search for
                zlib to link with]),
     [
        if test "x$withval" = "xyes"; then
                AC_CHECK_LIB([z], [zlibVersion], [], [
                        zlib="false"
                        AC_MSG_ERROR([libz not found])
                ])
                AC_CHECK_HEADERS([zlib.h])
        elif test "x$withval" != "xno"; then
                AC_MSG_CHECKING([for zlib in $withval])
                LDFLAGS="-L$withval/lib -lz $LDFLAGS "
                CFLAGS="-I$withval/include $CFLAGS"
                if test -r "$withval/lib/libz.a" -a -r "$withval/include/zlib.h"; then
                        AC_DEFINE([HAVE_LIBZ], [1], [Define if you have zlib library])
                        AC_DEFINE([HAVE_ZLIB_H], [1], [Define if you have zlib header])
                        AC_MSG_RESULT([ok])
                else
                        zlib="false"
                        AC_MSG_ERROR([zlib not found in $withval])
                fi
        else
                zlib="false"
        fi
     ],[
        AC_CHECK_LIB([z], [zlibVersion], [], [
                zlib="false"
                AC_MSG_ERROR([libz not found])
        ])
        AC_CHECK_HEADERS([zlib.h])
     ]
)

# ---------------------------------------------------------------------------
# Libraries 
# ---------------------------------------------------------------------------

AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([POSIX thread library is required])])
AC_CHECK_LIB([m], [round], [], [AC_MSG_ERROR([Math library is required])])

# ---------------------------------------------------------------------------
# Header files 
# ---------------------------------------------------------------------------

AC_HEADER_STDC
AC_CHECK_HEADERS([ctype.h \
                  errno.h \
                  execinfo.h \
                  fcntl.h \
                  ifaddrs.h \
                  kstat.h \
                  limits.h \
                  net/if_dl.h \
                  net/if_media.h\
                  netinet/in.h \
                  poll.h \
                  pthread.h \
                  setjmp.h \
                  signal.h \
                  stdarg.h \
                  stdio.h \
                  string.h \
                  strings.h \
                  stropts.h \
                  sys/dirent.h \
                  sys/event.h \
                  sys/filio.h \
                  sys/ioctl.h \
                  sys/poll.h \
                  sys/protosw.h \
                  sys/random.h \
                  sys/sendfile.h \
                  sys/socket.h \
                  sys/sysctl.h \
                  sys/time.h \
                  sys/types.h \
                  unistd.h \
                  usersec.h])
AC_CHECK_HEADERS([net/if.h net/route.h], [], [],
        [
         #ifdef HAVE_SYS_TYPES_H
         #include <sys/types.h>
         #endif
         #if HAVE_SYS_SOCKET_H
         #include <sys/socket.h>
         #endif
         #if HAVE_NETINET_IN_SYSTM_H
         #include <netinet/in.h>
         #endif
         #if HAVE_NETINET_IN_SYSTM_H
         #include <netinet/in_systm.h>
         #endif
         #if HAVE_NETINET_IP_H
         #include <netinet/ip.h>
         #endif
        ])
AC_CHECK_HEADERS([ \
        libperfstat.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_PROTOSW_H
         #include <sys/protosw.h>
         #endif
        ])

# ------------------------------------------------------------------------
# Types
# ------------------------------------------------------------------------

AC_CHECK_TYPES([uchar_t])

# ------------------------------------------------------------------------
# Functions 
# ------------------------------------------------------------------------

# Require a working setjmp
AC_CHECK_DECLS([setjmp], [], [AC_MSG_FAILURE([setjmp is required])], [[#include <setjmp.h>]])

# Require that we have vsnprintf that conforms to c99. I.e. does bounds check
AC_CHECK_FUNC([vsnprintf], [], [AC_MSG_FAILURE([vsnprintf is required])])

AC_CHECK_FUNCS([timegm getgrouplist getrandom arc4random_buf])

# ------------------------------------------------------------------------
# Architecture/OS
# ------------------------------------------------------------------------

architecture=`uname`
if test "$architecture" = "Linux"  
then
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_DEFINE([LINUX], 1, [Define to 1 if the system is Linux])
elif test "$architecture" = "FreeBSD"
then
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_DEFINE([FREEBSD], 1, [Define to 1 if the system is FreeBSD])
elif test "$architecture" = "GNU/kFreeBSD"
then
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_DEFINE([FREEBSD], 1, [Define to 1 if the system is FreeBSD])
elif test "$architecture" = "OpenBSD"
then
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_DEFINE([OPENBSD], 1, [Define to 1 if the system is OpenBSD])
elif test "$architecture" = "DragonFly"
then
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_DEFINE([DRAGONFLY], 1, [Define to 1 if the system is DragonFly])
elif test "$architecture" = "Darwin"
then
   CFLAGS="$CFLAGS -DREENTRANT"
   AC_DEFINE([DARWIN], 1, [Define to 1 if the system is OSX])
elif test "$architecture" = "SunOS"
then
   LIBS="$LIBS -lsocket -lnsl -lkstat"
   CFLAGS="$CFLAGS -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -D__EXTENSIONS__ -m64"
   LDFLAGS="$LDFLAGS -m64"
   if test `uname -m` != "i86pc"
   then
       CFLAGS="$CFLAGS -mtune=v9"
       LDFLAGS="$LDFLAGS -mtune=v9"
   fi
   AC_DEFINE([SOLARIS], 1, [Define to 1 if the system is SOLARIS])
elif test "$architecture" = "NetBSD"
then
   CFLAGS="$CFLAGS -D_REENTRANT -Wno-char-subscripts"
   AC_DEFINE([NETBSD], 1, [Define to 1 if the system is NETBSD])
elif test "$architecture" = "AIX"
then
   CFLAGS=`echo $CFLAGS|sed 's/-g//'`
   CFLAGS="$CFLAGS -D_THREAD_SAFE -D_REENTRANT"
   AC_DEFINE([AIX], 1, [Define to 1 if the system is AIX])
   LIBS="$LIBS -lcfg -lodm -lperfstat"
else
   AC_MSG_ERROR([Architecture not supported: ${architecture}])
fi

# ---------------------------------------------------------------------------
# Compiler 
# ---------------------------------------------------------------------------

AC_PROG_CC
AC_PROG_CXX
AC_C_CONST
AC_C_BIGENDIAN
# Define _GNU_SOURCE so we can have Posix headers etc included. We use the
# -std=cXX compiler switch which only include a minimum of C headers
CFLAGS="$CFLAGS -D_GNU_SOURCE"

# Compiler; tune warnings and make the char type unsigned
CFLAGS="$CFLAGS -Wall -Wunused -Wno-unused-label -funsigned-char";
# does this compiler support -Wno-pointer-sign ?
svd_CFLAGS="$CFLAGS"
CFLAGS="-Wno-pointer-sign $CFLAGS"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [return 0;])], [], [CFLAGS="$svd_CFLAGS"])
# does this compiler support -Wno-address ?
svd_CFLAGS="$CFLAGS"
CFLAGS="-Wno-address $CFLAGS"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [return 0;])], [], [CFLAGS="$svd_CFLAGS"])

# Require at least C99 and use C11 if available
AC_COMPUTE_INT([STDC_VERSION],[__STDC_VERSION__],,[STDC_VERSION=0])
AS_IF([test "$STDC_VERSION" -ge 201112],[CFLAGS="$CFLAGS -std=c11"],[CFLAGS="$CFLAGS -std=c99"])
AC_CHECK_HEADERS([stdint.h stdbool.h], [], [AC_MSG_ERROR([toolchain does not have C99 headers])])

# ------------------------------------------------------------------------
# IPv6 Support
# ------------------------------------------------------------------------

AC_ARG_WITH(ipv6,
    AS_HELP_STRING([--without-ipv6], [Disable the IPv6 support (default: check)]),
    [
        if test "x$withval" = "xno"
        then
            with_ipv6=0
        elif test "x$withval" = "xyes"
        then
            with_ipv6=1
            AC_DEFINE([HAVE_IPV6], 1, [Define to 1 if the system supports IPv6])
        fi
    ],
    [
        # Note inverse test. Check by default
        AC_MSG_CHECKING(for IPv6 support)
        AC_CACHE_VAL(ac_cv_ipv6,
                AC_RUN_IFELSE([AC_LANG_SOURCE([[
                #include <sys/types.h>
                #include <sys/socket.h>
                #include <netinet/in.h>
                /* Make sure the definitions for AF_INET6 and struct sockaddr_in6
                 * are defined, and that we can actually create an IPv6 TCP socket.*/
                main()
                {
                        int fd;
                        struct sockaddr_in6 foo;
                        fd = socket(AF_INET6, SOCK_STREAM, 0);
                        exit(fd >= 0 ? 0 : 1);
                }]])],
                [ac_cv_ipv6=yes],
                [ac_cv_ipv6=no],
                [ac_cv_ipv6=no])
        )
        AC_MSG_RESULT($ac_cv_ipv6)

        if test $ac_cv_ipv6 = yes
        then
                with_ipv6=1
                AC_DEFINE([HAVE_IPV6], 1, [Define to 1 if the system supports IPv6])
        else
                with_ipv6=0
        fi
    ]
)


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

AC_CONFIG_HEADERS(src/xconfig.h)
AC_CONFIG_FILES([Makefile test/Makefile])
AC_OUTPUT

cat <<EOT
+------------------------------------------------------------+
| License:                                                   |
| This is Open Source Software and use is subject to the GNU |
| AFFERO GENERAL PUBLIC LICENSE version 3, available in this |
| distribution in the file COPYING.                          |
|                                                            |
| By continuing this installation process, you are bound by  | 
| the terms of this license agreement. If you do not agree   |
| with the terms of this license, you must abort the         |
| installation process at this point.                        |
+------------------------------------------------------------+
| Libmonit is configured as follows:                         |
|                                                            |
EOT

if test "x1" = "x$OPTIMIZED"; then
echo "|   Optimized:                                    ENABLED    |"
else
echo "|   Optimized:                                    DISABLED   |"
fi
if test "xfalse" = "x$profile"; then
echo "|   Profiling:                                    DISABLED   |"
else
echo "|   Profiling:                                    ENABLED    |"
fi
if test "xfalse" = "x$zlib"; then
echo "|   Compression:                                  DISABLED   |"
else
echo "|   Compression:                                  ENABLED    |"
fi
echo "+------------------------------------------------------------+"


