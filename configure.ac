# Process this file with bootstrap to produce a configure script.

# autoconf requirement
AC_PREREQ([2.53])

# Note: in  case of beta subversion, use underscore "_" rather then dash "-"
# since RPM doesn't allow dash in Version
# Example: 5.0_beta2
AC_INIT([monit], [5.27.2], [monit-general@nongnu.org])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/monit.c])
AC_CONFIG_SUBDIRS([libmonit])
AC_CONFIG_COMMANDS([libtool_patch],[test `uname` = "OpenBSD" && perl -p -i -e "s/deplibs_check_method=.*/deplibs_check_method=pass_all/g" libtool])
AC_CONFIG_COMMANDS([monitrc], [chmod 600 monitrc])

# ------------------------------------------------------------------------
# Programs
# ------------------------------------------------------------------------

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CHECK_PROGS([YACC], ['bison -y' byacc yacc], [no], [$PATH:/usr/local/bin:/usr/bin])
if test "x$YACC" = "xno"; then
	# Require bison unless y.tab.c already is built
	if test ! -f src/y.tab.c; then
                AC_MSG_ERROR([Monit require bison, byacc or yacc. Download bison from http://www.gnu.org/software/bison/])
	fi
fi
AC_PATH_PROG([FLEX], [flex], [no], [$PATH:/usr/local/bin:/usr/bin])
if test "x$FLEX" = "xno"; then
	# Require flex unless lex.yy.c already is built
	if test ! -f src/lex.yy.c; then
                AC_MSG_ERROR([flex is required. Download from http://www.gnu.org/software/flex/])
	fi
fi
AC_PATH_PROG([POD2MAN], [pod2man], [no], [$PATH:/usr/local/bin:/usr/bin])
if test "x$POD2MAN" = "xno"; then
	# Require pod2man unless monit.1 already is built
	if test ! -f monit.1; then
		AC_MSG_ERROR([pod2man is required to build the monit.1 man file.])
	fi
else
	POD2MANFLAGS="--center 'User Commands' --release AC_PACKAGE_VERSION --date='www.mmonit.com' --lax"
	AC_SUBST([POD2MANFLAGS])
fi

AX_CHECK_COMPILE_FLAG([-Wextra], [CFLAGS="$CFLAGS -Wextra"])
if test `uname` != "AIX"; then
        AX_CHECK_COMPILE_FLAG([-fstack-protector-all], [CFLAGS="$CFLAGS -fstack-protector-all"])
        AX_CHECK_COMPILE_FLAG([-fcf-protection=full], [CFLAGS="$CFLAGS -fcf-protection=full"])
        AX_CHECK_COMPILE_FLAG([-fstack-clash-protection], [CFLAGS="$CFLAGS -fstack-clash-protection"])
fi


# ------------------------------------------------------------------------
# Libtool
# ------------------------------------------------------------------------

AC_DISABLE_STATIC
LT_INIT


# ------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------

# Check for libraries
AC_CHECK_LIB([socket], [socket])
AC_CHECK_LIB([inet],   [socket])
AC_CHECK_LIB([nsl],    [inet_addr])
AC_CHECK_LIB([resolv], [inet_aton])
AC_CHECK_LIB([c], [crypt], [:], [AC_CHECK_LIB([crypt], [crypt])])
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([POSIX thread library is required])])


# ------------------------------------------------------------------------
# Header files
# ------------------------------------------------------------------------

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_STAT
AC_HEADER_TIME

AC_CHECK_HEADERS([ \
        alloca.h \
	arpa/inet.h \
	asm/page.h \
	asm/param.h \
	cf.h \
	crt_externs.h \
	ctype.h \
	crypt.h \
	CoreFoundation/CoreFoundation.h \
	devstat.h \
	dirent.h \
	DiskArbitration/DiskArbitration.h \
	errno.h \
	execinfo.h \
	fcntl.h \
	getopt.h \
	glob.h \
	grp.h \
	ifaddrs.h \
	IOKit/storage/IOBlockStorageDriver.h \
	kinfo.h \
	kvm.h \
	paths.h \
	kstat.h \
	libzfs.h \
	zone.h \
	sys/protosw.h \
	libproc.h \
	limits.h \
	loadavg.h \
	locale.h \
	lvm.h \
        mach/host_info.h \
        mach/mach.h \
        mach/mach_host.h \
	memory.h \
	mntent.h \
	netdb.h \
        sys/socket.h \
	netinet/in.h \
	netinet/tcp.h \
        netinet/in_systm.h \
        pam/pam_appl.h \
        security/pam_appl.h \
	poll.h \
	procfs.h \
	sys/procfs.h \
	procinfo.h \
	pthread.h \
	pwd.h \
	regex.h \
	setjmp.h \
	signal.h \
	stdarg.h \
        stddef.h \
	stdio.h \
	string.h \
	strings.h \
	stropts.h \
	sys/cfgodm.h \
	sys/cfgdb.h \
	sys/dk.h \
	sys/dkstat.h \
	sys/disk.h \
	sys/filio.h \
	sys/fs/zfs.h \
	sys/instance.h \
	sys/ioctl.h \
	sys/iostat.h \
	sys/loadavg.h \
	sys/lock.h \
	sys/mntent.h \
	sys/mnttab.h \
	sys/mutex.h \
	sys/nlist.h \
	sys/nvpair.h \
	sys/param.h \
	sys/pstat.h \
	sys/queue.h \
	sys/resource.h \
	sys/sched.h \
	sys/statfs.h \
	sys/statvfs.h \
	sys/sysinfo.h \
	sys/sysmacros.h \
	sys/systemcfg.h \
	sys/time.h \
	sys/tree.h \
	sys/types.h \
	sys/un.h \
	sys/utsname.h \
        sys/var.h \
        sys/vmmeter.h \
        sys/vm_usage.h \
	sys/vfs.h \
	syslog.h \
	unistd.h \
	utmpx.h \
        uvm/uvm_extern.h \
        uvm/uvm_param.h \
        vm/vm.h \
        net/if_media.h \
        net/if_dl.h \
        net/route.h
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

AC_CHECK_HEADERS([ \
	netinet/ip.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_TYPES_H
         #include <sys/types.h>
         #endif
         #if HAVE_NETINET_IN_SYSTM_H
         #include <netinet/in_systm.h>
         #endif
         #if HAVE_NETINET_IN_SYSTM_H
         #include <netinet/in.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
	net/if.h \
	netinet/ip_icmp.h \
        ],
        [],
        [],
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
	netinet/icmp6.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_TYPES_H
         #include <sys/types.h>
         #endif
         #if HAVE_NETINET_IP_H
         #include <netinet/in.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
        sys/sysctl.h \
        sys/mount.h \
        sys/proc.h \
        sys/swap.h \
	sys/ucred.h \
        sys/user.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_PARAM_H
         #include <sys/param.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
	machine/vmparam.h \
        vm/pmap.h \
        machine/pmap.h \
        vm/vm_map.h \
	vm/vm_object.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_PARAM_H
         #include <sys/param.h>
         #endif
         #ifdef HAVE_SYS_QUEUE_H
         #include <sys/queue.h>
         #endif
         #ifdef HAVE_SYS_LOCK_H
         #include <sys/lock.h>
         #endif
         #ifdef HAVE_SYS_MUTEX_H
         #include <sys/mutex.h>
         #endif
         #ifdef HAVE_VM_VM_H
         #include <vm/vm.h>
         #endif
         #ifdef HAVE_VM_PMAP_H
         #include <vm/pmap.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
        sys/resourcevar.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_TIME_H
         #include <sys/time.h>
         #endif
         #ifdef HAVE_SYS_RESOURCE_H
         #include <sys/resource.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
	uvm/uvm_map.h \
	uvm/uvm_pmap.h \
	uvm/uvm_object.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_TIME_H
         #include <sys/time.h>
         #endif
         #ifdef HAVE_SYS_LOCK_H
         #include <sys/lock.h>
         #endif
         #ifdef HAVE_SYS_TREE_H
         #include <sys/tree.h>
         #endif
         #ifdef HAVE_UVM_UVM_EXTERN_H
         #include <uvm/uvm_extern.h>
         #endif
        ])

AC_CHECK_HEADERS([ \
	uvm/uvm.h \
        ],
        [],
        [],
        [
         #ifdef HAVE_SYS_MUTEX_H
         #include <sys/mutex.h>
         #endif
         #ifdef HAVE_SYS_TYPES_H
         #include <sys/types.h>
         #endif
         #ifdef HAVE_SYS_PARAM_H
         #include <sys/param.h>
         #endif
         #ifdef HAVE_UVM_UVM_PARAM_H
         #include <uvm/uvm_param.h>
         #endif
        ])

# ------------------------------------------------------------------------
# Types
# ------------------------------------------------------------------------

AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_PID_T

# Check for structures.
AC_STRUCT_TM
AC_CHECK_MEMBERS([struct tm.tm_gmtoff])


# ------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_CHECK_FUNCS(statfs)
AC_CHECK_FUNCS(statvfs)
AC_CHECK_FUNCS(setlocale)
AC_CHECK_FUNCS(getaddrinfo)
AC_CHECK_FUNCS(syslog)
AC_CHECK_FUNCS(vsyslog)
AC_CHECK_FUNCS(backtrace)
AC_CHECK_FUNCS(getloadavg)
AC_CHECK_FUNCS(getopt_long)


# ------------------------------------------------------------------------
# Compiler
# ------------------------------------------------------------------------

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
                AC_RUN_IFELSE([
                AC_LANG_SOURCE([[
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


# ------------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------------

# Find the right directory to put the root-mode PID file in
AC_MSG_CHECKING([pid file location])
if test -d "/run"
then
	piddir="/run"
elif test -d "/var/run"; then
        piddir="/var/run"
elif test -d "/etc"; then
        piddir="/etc"
fi

AC_DEFINE_UNQUOTED([PIDDIR], "$piddir",
	  [Define to the pid storage directory.])
AC_MSG_RESULT([$piddir])

# Test mounted filesystem description file
if test -f "/etc/mtab"
then
  AC_DEFINE([HAVE_MTAB], 1, [Define to 1 if you have /etc/mtab])
elif test -f "/etc/mnttab"; then
  AC_DEFINE([HAVE_MNTTAB], 1, [Define to 1 if you have /etc/mnttab])
fi


# ------------------------------------------------------------------------
# Architecture/OS detection
# ------------------------------------------------------------------------

# Backward compatibility until we get ride of arch settings
architecture=`uname`
if test "$architecture" = "SunOS"
then
   ARCH="SOLARIS"
   CFLAGS="$CFLAGS -D _REENTRANT -D_POSIX_PTHREAD_SEMANTICS -D__EXTENSIONS__ -m64"
   LDFLAGS="$LDFLAGS -m64"
   AC_CHECK_LIB([zfs], [libzfs_init])
   AC_CHECK_LIB([nvpair], [nvlist_free])
   AC_CHECK_LIB([kstat], [kstat_open])
   if test `uname -m` = "i86pc"
   then
      if test "x$GCC" = "xyes"
      then
            CFLAGS="$CFLAGS -mtune=opteron"
            LDFLAGS="$LDFLAGS -mtune=opteron"
      else
            CFLAGS="$CFLAGS -xarch=sse2"
            LDFLAGS="$LDFLAGS -xarch=sse2"
      fi
   else
      if test "x$GCC" = "xyes"
      then
            CFLAGS="$CFLAGS -mtune=v9"
            LDFLAGS="$LDFLAGS -mtune=v9"
      else
            CFLAGS="$CFLAGS -xarch=sparc"
            LDFLAGS="$LDFLAGS -xarch=sparc"
      fi
   fi
elif test "$architecture" = "Linux"
then
   ARCH="LINUX"
   CFLAGS="$CFLAGS -D _REENTRANT"
   LDFLAGS="$LDFLAGS -rdynamic"
elif test "$architecture" = "OpenBSD"
then
   ARCH="OPENBSD"
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_CHECK_LIB([kvm], [kvm_open])
   with_pam=0 # No PAM on OpenBSD (supports BSD Auth API instead of PAM)
elif test "$architecture" = "FreeBSD"
then
   ARCH="FREEBSD"
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_CHECK_LIB([devstat], [devstat_getnumdevs])
   AC_CHECK_LIB([kvm], [kvm_open])
elif test "$architecture" = "GNU/kFreeBSD"
then
   ARCH="FREEBSD"
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_CHECK_LIB([devstat], [devstat_getnumdevs])
   AC_CHECK_LIB([kvm], [kvm_open])
elif test "$architecture" = "NetBSD"
then
   ARCH="NETBSD"
   CFLAGS="$CFLAGS -D _REENTRANT -Wno-char-subscripts"
   AC_CHECK_LIB([kvm], [kvm_open])
elif test "$architecture" = "DragonFly"
then
   ARCH="DRAGONFLY"
   CFLAGS="$CFLAGS -D _REENTRANT"
   AC_CHECK_LIB([kvm], [kvm_open])
   AC_CHECK_LIB([devstat], [getnumdevs])
elif test "$architecture" = "Darwin"
then
   ARCH="DARWIN"
   CFLAGS="$CFLAGS -DREENTRANT -no-cpp-precomp -DNEED_SOCKLEN_T_DEFINED"
   LDFLAGS="$LDFLAGS -Wl,-search_paths_first"
   AC_CHECK_LIB([kvm], [kvm_open])
   LIBS="$LIBS -framework System -framework CoreFoundation -framework DiskArbitration -framework IOKit -multiply_defined suppress"
elif test "$architecture" = "AIX"
then
   ARCH="AIX"
   CFLAGS=`echo $CFLAGS|sed 's/-g//g'`
   CFLAGS="$CFLAGS -D_THREAD_SAFE -D_REENTRANT"
   LIBS="$LIBS -lodm -lperfstat -lm"
else
   AC_MSG_WARN([Architecture not supported: ${architecture}])
   CFLAGS="$CFLAGS -D _REENTRANT"
   ARCH="UNKNOWN"
fi
AC_SUBST(ARCH)


# ------------------------------------------------------------------------
# Large files code
# ------------------------------------------------------------------------

# Check if we want to have large files support
AC_MSG_CHECKING([for large files support])
AC_ARG_WITH(largefiles,
    [  --without-largefiles    disable large files support (default: enabled)],
    [
        dnl Check the withvalue
        if test "x$withval" = "xno" ; then
            with_largefiles=0
            AC_MSG_RESULT([disabled])
        fi
        if test "x$withval" = "xyes" ; then
            with_largefiles=1
            AC_MSG_RESULT([enabled])
        fi
    ],
    [
	if test `uname` = "AIX"
	then
	    with_largefiles=0
	    AC_MSG_RESULT([disabled])
	else
	    with_largefiles=1
	    AC_MSG_RESULT([enabled])
	fi
    ]
)

# Settings for largefiles support
if test $with_largefiles -eq 1; then
        AC_SYS_LARGEFILE
        AC_DEFINE([HAVE_LARGEFILES], 1, [Define to 1 if you have large files support])
fi


# ------------------------------------------------------------------------
# zlib Code
# ------------------------------------------------------------------------

AC_ARG_WITH([zlib],
        AS_HELP_STRING([--with-zlib(=<path>)],
                [Link Monit with zlib. An optional path argument may
                be given to specify the top-level directory to search for
                zlib to link with]),
     [
        if test "x$withval" = "xyes"; then
                AC_CHECK_LIB([z], [zlibVersion], [], [AC_MSG_ERROR([libz not found])])
                with_zlib=1
                AC_CHECK_HEADERS([zlib.h])
        elif test "x$withval" != "xno"; then
                AC_MSG_CHECKING([for zlib in $withval])
                LDFLAGS="-L$withval/lib -lz $LDFLAGS "
                CFLAGS="-I$withval/include $CFLAGS"
                if test -r "$withval/lib/libz.a" -a -r "$withval/include/zlib.h"; then
                        with_zlib=1
                        AC_DEFINE([HAVE_LIBZ], [1], [Define if you have zlib library])
                        AC_DEFINE([HAVE_ZLIB_H], [1], [Define if you have zlib header])
                        AC_MSG_RESULT([ok])
                else
                        with_zlib=0
                        AC_MSG_ERROR([zlib not found in $withval])
                fi
        else
                with_zlib=0
        fi
     ],[
        AC_CHECK_LIB([z], [zlibVersion], [], [AC_MSG_ERROR([libz not found])])
        with_zlib=1
        AC_CHECK_HEADERS([zlib.h])
     ]
)

# ------------------------------------------------------------------------
# PAM Code
# ------------------------------------------------------------------------

AC_MSG_CHECKING([for PAM support])
AC_ARG_WITH(pam,
    [  --without-pam           disable the use of pam (default: enabled)],
    [
        dnl Check the withvalue
        if test "x$withval" = "xno" || test "x$with_pam" = "x0"; then
                with_pam=0
                AC_MSG_RESULT([disabled])
        else
                with_pam=1
                AC_MSG_RESULT([enabled])
        fi
    ],
    [
        # Note inverse test. On by default
        with_pam=1
        AC_MSG_RESULT([enabled])
    ]
)

if test $with_pam -eq 1; then
        AC_CHECK_LIB([pam], [pam_start], [], [AC_MSG_ERROR([PAM enabled but headers or library not found, install the PAM development support or run configure --without-pam])])
fi


# ------------------------------------------------------------------------
# AddressSanitizer
# ------------------------------------------------------------------------

AC_MSG_CHECKING([for AddressSanitizer support])
AC_ARG_WITH(asan,
    [  --with-asan             enable the use of AddressSanitizer (default: disabled)],
    [
        dnl Check the withvalue
        if test "x$withval" = "xno" ; then
            with_asan=0
            AC_MSG_RESULT([disabled])
        fi
        if test "x$withval" = "xyes" ; then
            with_asan=1
            AC_MSG_RESULT([enabled])
        fi
    ],
    [
        with_asan=0
        AC_MSG_RESULT([disabled])
    ]
)

if test $with_asan -eq 1; then
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
        AX_CHECK_COMPILE_FLAG([-fsanitize=undefined], [CFLAGS="$CFLAGS -fsanitize=undefined"])
        AC_DEFINE([HAVE_ASAN], 1, [Define to 1 if you have address sanitizer.])
fi


# ------------------------------------------------------------------------
# SSL Code
# ------------------------------------------------------------------------

# Check for ssl includes
checksslincldir() { :
    if test -f "$1/openssl/ssl.h"; then
        sslincldir="$1"
        return 0
    fi
    return 1
}

# Check for ssl libraries
checkssllibdirdynamic() { :
    CRYPTOLIB=`ls -1 $1/libcrypto.so* $1/libcrypto.dylib* 2>/dev/null | wc -l`
    SSLLIB=`ls -1 $1/libssl.so* $1/libssl.dylib* 2>/dev/null | wc -l`
    if test "(" $CRYPTOLIB -gt 0 -a $SSLLIB -gt 0 ")"
    then
        ssllibdir="$1"
        return 0
    fi
    return 1
}

checkssllibdirstatic() { :
    if test "(" -f "$1/libcrypto.a" ")"  -a \
            "(" -f "$1/libssl.a" ")" ; then
        ssllibdir="$1"
        return 0
    fi
    return 1
}

# Check if we want to have SSL

AC_MSG_CHECKING([for static SSL support])

AC_ARG_WITH(ssl-static,
    [  --with-ssl-static=DIR       location of SSL installation],
    [
        dnl Check the specified location only
        for dir in "$withval" "$withval/include"; do
            checksslincldir "$dir"
        done
        for dir in "$withval" "$withval/lib"; do
            checkssllibdirstatic "$dir" && break
        done
        with_sslstatic=1
        LDFLAGS="`echo $LDFLAGS | sed -e 's/-rdynamic/-ldl/g'`"
        AC_MSG_RESULT([enabled])
        AC_DEFINE([HAVE_OPENSSL], 1, [Define to 1 if you have openssl.])
        AC_SUBST(sslincldir)
        AC_SUBST(ssllibdir)
        CFLAGS="$CFLAGS -I$sslincldir"
        LIBS="$LIBS $ssllibdir/libssl.a $ssllibdir/libcrypto.a"
        if test `uname` = "Linux" && test `uname -m` = "aarch64"; then
            LIBS="$LIBS -ldl"
        fi
    ],
    [
	with_sslstatic=0
        AC_MSG_RESULT([disabled])
    ]
)

if test $with_sslstatic -eq 0
then
    AC_MSG_CHECKING([for SSL support])

    AC_ARG_WITH(ssl,
        [  --without-ssl           disable the use of ssl (default: enabled)],
        [
            dnl Check the withvalue
            if test "x$withval" = "xno" ; then
                with_ssl=0
                AC_MSG_RESULT([disabled])
            fi
            if test "x$withval" = "xyes" ; then
                with_ssl=1
                AC_MSG_RESULT([enabled])
            fi
        ],
        [
                # Note inverse test. On by default
                with_ssl=1
                AC_MSG_RESULT([enabled])
        ]
    )


    # Check for SSL directory
    if test $with_ssl -eq 1; then

        AC_ARG_WITH(ssl-dir,
            [  --with-ssl-dir=DIR       location of SSL installation],
            [
                dnl Check the specified location only
                for dir in "$withval" "$withval/include"; do
                	checksslincldir "$dir"
                done
                for dir in "$withval" "$withval/lib"; do
                    checkssllibdirdynamic "$dir" && break
                done
            ]
        )

        AC_MSG_CHECKING([for SSL include directory])
        AC_ARG_WITH(ssl-incl-dir,
            [  --with-ssl-incl-dir=DIR  location of installed SSL include files],
            [
                dnl Check the specified location only
                checksslincldir "$withval"
            ],
            [
                if test -z "$sslincldir"; then
                    dnl Search default locations of SSL includes
                    for maindir in /usr /usr/local /usr/lib /usr/pkg /var /opt /usr/sfw /opt/csw /opt/freeware; do
                        for dir in "$maindir/include"\
                                   "$maindir/include/openssl"\
                                   "$maindir/include/ssl"\
                                   "$maindir/ssl/include"; do
                            checksslincldir $dir && break 2
                        done
                    done
                fi
            ]
        )
        if test -z "$sslincldir"; then
            AC_MSG_RESULT([Not found])
            echo
            echo "Couldn't find your SSL header files."
            echo "Use --with-ssl-incl-dir option to fix this problem or disable"
            echo "the SSL support with --without-ssl"
            echo
            exit 1
        fi
        AC_MSG_RESULT([$sslincldir])

        AC_MSG_CHECKING([for SSL library directory])
        AC_ARG_WITH(ssl-lib-dir,
            [  --with-ssl-lib-dir=DIR   location of installed SSL library files],
            [
                dnl Check the specified location only
                checkssllibdirdynamic "$withval"
            ],
            [
                if test -z "$ssllibdir"; then
                    dnl Search default locations of SSL libraries
                    for maindir in "" \
                                   /usr \
                                   /usr/local \
                                   /usr/pkg \
                                   /var \
                                   /opt \
                                   /usr/sfw \
                                   /opt/csw \
                                   /opt/freeware; do
                        for dir in $maindir \
                                   $maindir/openssl \
                                   $maindir/ssl \
                                   $maindir/lib \
                                   $maindir/lib/openssl \
                                   $maindir/lib/ssl \
                                   $maindir/ssl/lib \
                                   $maindir/lib/64 \
                                   $maindir/lib/64/openssl \
                                   $maindir/lib/64/ssl \
                                   $maindir/ssl/lib/64 \
                                   $maindir/lib64 \
                                   $maindir/lib64/openssl \
                                   $maindir/lib64/ssl \
                                   $maindir/ssl/lib64 \
                                   $maindir/lib/${host} \
                                   $maindir/lib/${host_alias}; do
                            checkssllibdirdynamic $dir && break 2
                        done
                    done
                fi
            ]
        )
        if test -z "$ssllibdir"; then
            AC_MSG_RESULT([Not found])
            dnl Let the compiler find the library using default paths
            AC_CHECK_LIB([ssl], [SSL_new], [], [AC_MSG_ERROR([Could not find SSL library, please use --with-ssl-lib-dir option or disabled the SSL support using --without-ssl])])
            AC_CHECK_LIB([crypto],[CRYPTO_new_ex_data], [], [AC_MSG_ERROR([Could not find SSL library, please use --with-ssl-lib-dir option or disabled the SSL support using --without-ssl])])
        else
            AC_MSG_RESULT([$ssllibdir])
        fi

        AC_DEFINE([HAVE_OPENSSL], 1, [Define to 1 if you have openssl.])
        AC_SUBST(sslincldir)
        AC_SUBST(ssllibdir)
    fi

    # Add SSL includes and libraries
    if test "$sslincldir" -a "$ssllibdir"
    then
        if test "x$ARCH" = "xDARWIN"; then
         # Darwin already knows about ssldirs
         LIBS="$LIBS -lssl -lcrypto"
        elif test -f "/usr/kerberos/include/krb5.h"; then
         # Redhat 9 compilation fix:
         CFLAGS="$CFLAGS -I$sslincldir -I/usr/kerberos/include"
         LIBS="$LIBS -L$ssllibdir -lssl -lcrypto"
        else
         CFLAGS="$CFLAGS -I$sslincldir"
         LIBS="$LIBS -L$ssllibdir -lssl -lcrypto"
        fi
    fi
fi
# Check TLS version
if test $with_sslstatic -eq 1 || test $with_ssl -eq 1; then
        if test "x$sslincldir" != "x"; then
                CFLAGS="$CFLAGS -I$sslincldir"
        fi
        if test "x$ssllibdir" != "x"; then
                LIBS="$LIBS -L$ssllibdir"
        fi

        AC_MSG_CHECKING([for SSLv2])
        AC_LINK_IFELSE(
                [AC_LANG_PROGRAM([#include <openssl/ssl.h>], [SSLv2_client_method()])],
                [sslv2=yes],
                [sslv2=no])
        AC_MSG_RESULT($sslv2)
        if test "$sslv2" = "yes" ; then
                AC_DEFINE([HAVE_SSLV2], 1, [Define to 1 if you have openssl with SSLv2])
        fi

        AC_CHECK_DECL([SSL_OP_NO_TLSv1_1], [AC_DEFINE([HAVE_TLSV1_1], 1, [Define to 1 if you have openssl with TLSv1.1])], [], [[#include <openssl/ssl.h>]])
        AC_CHECK_DECL([SSL_OP_NO_TLSv1_2], [AC_DEFINE([HAVE_TLSV1_2], 1, [Define to 1 if you have openssl with TLSv1.2])], [], [[#include <openssl/ssl.h>]])
        AC_CHECK_DECL([SSL_OP_NO_TLSv1_3], [AC_DEFINE([HAVE_TLSV1_3], 1, [Define to 1 if you have openssl with TLSv1.3])], [], [[#include <openssl/ssl.h>]])

        AC_MSG_CHECKING([for EC_KEY support])
        AC_LINK_IFELSE(
                [AC_LANG_PROGRAM([#include <openssl/ssl.h>], [EC_KEY_new_by_curve_name(0)])],
                [ec=yes],
                [ec=no])
        AC_MSG_RESULT($ec)
        if test "$ec" = "yes" ; then
                AC_DEFINE([HAVE_EC_KEY], 1, [Define to 1 if you have openssl with EC_KEY])
        fi

        AC_MSG_CHECKING([for ASN1_TIME_diff support])
        AC_LINK_IFELSE(
                [AC_LANG_PROGRAM([#include <openssl/ssl.h>], [ASN1_TIME_diff(0, 0, 0, 0)])],
                [asn1timediff=yes],
                [asn1timediff=no])
        AC_MSG_RESULT($asn1timediff)
        if test "$asn1timediff" = "yes" ; then
                AC_DEFINE([HAVE_ASN1_TIME_DIFF], 1, [Define to 1 if you have openssl with ASN1_TIME_diff])
        fi
fi


# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------

AC_ARG_ENABLE(optimized,
        AS_HELP_STRING([--enable-optimized],
                [Build software optimized]),
    [
        CFLAGS=`echo $CFLAGS|sed 's/-O.//g'`
        if test "x$enableval" = "xyes" ; then
                CFLAGS=`echo $CFLAGS|sed 's/-g[[^ ]]*//g'`
                CFLAGS=`echo $CFLAGS|sed 's/-O.//g'`
                CFLAGS="$CFLAGS -O3 -DNDEBUG"
                enable_optimized=1
        else
                enable_optimized=0
        fi
    ],
    [
        enable_optimized=0
    ]
)

AC_ARG_ENABLE(profiling,
        AS_HELP_STRING([--enable-profiling],
                [Build with debug and profiling options]),
    [
        if test "x$enableval" = "xyes" ; then
                CFLAGS=`echo $CFLAGS|sed 's/-g.//g'`
                CFLAGS=`echo $CFLAGS|sed 's/-O.//g'`
                CFLAGS="$CFLAGS -g -pg -fprofile-arcs -ftest-coverage"
                enable_profile=1
        else
                enable_profile=0
        fi
    ],
    [
        enable_profile=0
    ]
)

AC_ARG_ENABLE([codesign],
        AS_HELP_STRING([--enable-codesign=identity],
                [Add code signature to the monit binary on macOS]),
     [
        if test "x$enableval" = "xno" ; then
                enable_codesign=0
        else
                AC_MSG_CHECKING([for validity of signing identity])
                if test "x$enableval" = "xyes"; then
                        AC_MSG_ERROR([Please provide a signing identity])
                else
                        if test -n "$(security find-identity -v|grep $enableval)"; then
                                enable_codesign=1
                                AC_SUBST([CODESIGN_IDENTITY], [$enableval])
                                AC_MSG_RESULT(yes)
                        else
                                AC_MSG_ERROR([Signing identity not found])
                        fi
                fi
        fi
     ],[enable_codesign=0]
)
AM_CONDITIONAL([WITH_CODESIGN], [test $enable_codesign -eq 1])


# ------------------------------------------------------------------------
# Outputs
# ------------------------------------------------------------------------

AH_BOTTOM([
/* Mask out GCC __attribute__ extension for non-gcc compilers. */
#ifndef __GNUC__
#define __attribute__(x)
#endif
])

AC_CONFIG_HEADER([src/config.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([system/startup/monit.upstart])
AC_CONFIG_FILES([system/startup/monit.service])

AC_OUTPUT

echo
echo "Monit Build Information:"
echo
echo "                Architecture: ${ARCH}"
if test $with_sslstatic -eq 1 || test $with_ssl -eq 1; then
echo "       SSL include directory: ${sslincldir}"
echo "       SSL library directory: ${ssllibdir}"
fi
echo "              Compiler flags: ${CFLAGS}"
echo "                Linker flags: ${LIBS}"
echo "           pid file location: ${piddir}"
echo "           Install directory: ${prefix}"
echo

AX_INFO_AGPL()
AX_INFO_TITLE([Monit has been configured with the following options:])
AX_INFO_ENABLED([Compression:],           [test $with_zlib -eq 1])
AX_INFO_ENABLED([PAM support:],           [test $with_pam -eq 1])
AX_INFO_ENABLED([SSL support:],           [test $with_sslstatic -eq 1 || test $with_ssl -eq 1])
AX_INFO_ENABLED([Large files support:],   [test $with_largefiles -eq 1])
AX_INFO_ENABLED([ASAN support:],          [test $with_asan -eq 1])
AX_INFO_ENABLED([IPv6 support:],          [test $with_ipv6 -eq 1])
AX_INFO_ENABLED([Optimized:],             [test $enable_optimized -eq 1])
AX_INFO_ENABLED([Profiling:],             [test $enable_profile -eq 1])
if test "x$ARCH" = "xDARWIN"; then
AX_INFO_SEPARATOR()
AX_INFO_ENABLED([MacOS Code Signing:],    [test $enable_codesign -eq 1])
fi
AX_INFO_BREAK()
