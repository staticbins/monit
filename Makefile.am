# Copyright (C) Tildeslash Ltd. All rights reserved.

AUTOMAKE_OPTIONS = foreign no-dependencies subdir-objects
ACLOCAL_AMFLAGS	 = -I m4

EXTRA_DIST	= COPYING CONTRIBUTORS bootstrap doc src config monitrc system libmonit monit.1

SUBDIRS		= libmonit

CC		= @CC@
FLEX		= @FLEX@
FLEXFLAGS	= -i
YACC		= @YACC@
YACCFLAGS	= -dvt
POD2MAN		= @POD2MAN@
POD2MANFLAGS	= @POD2MANFLAGS@

AM_CPPFLAGS	= $(CPPFLAGS) $(EXTCPPFLAGS) -D@ARCH@ -DSYSCONFDIR="\"@sysconfdir@\"" -I./src -I./src/device -I./src/http -I./src/notification -I./src/process -I./src/protocols -I./src/ssl -I./src/terminal -I./libmonit/src
AM_LDFLAGS	= $(LDFLAGS) $(EXTLDFLAGS) -L./lib/

bin_PROGRAMS	= monit
monit_SOURCES	= src/y.tab.c \
		  src/lex.yy.c \
		  src/monit.c \
		  src/alert.c \
		  src/control.c \
		  src/daemonize.c \
		  src/env.c \
		  src/event.c \
		  src/file.c \
		  src/gc.c \
		  src/http.c \
		  src/log.c \
		  src/md5.c \
		  src/md5_crypt.c \
		  src/net/net.c \
                  src/net/socket.c \
                  src/net/Link.c \
		  src/sha1.c \
		  src/checksum.c \
		  src/signal.c \
		  src/spawn.c \
		  src/state.c \
		  src/util.c \
		  src/validate.c \
		  src/device/device_common.c \
		  src/device/sysdep_@ARCH@.c \
		  src/http/base64.c \
		  src/http/cervlet.c \
		  src/http/client.c \
		  src/http/engine.c \
		  src/http/xml.c \
		  src/http/processor.c \
		  src/notification/Address.c \
		  src/notification/MMonit.c \
		  src/notification/SMTP.c \
		  src/process/ProcessTree.c \
		  src/process/sysdep_@ARCH@.c \
		  src/protocols/apache_status.c \
		  src/protocols/clamav.c \
		  src/protocols/default.c \
		  src/protocols/dns.c \
		  src/protocols/dwp.c \
		  src/protocols/fail2ban.c \
		  src/protocols/ftp.c \
		  src/protocols/generic.c \
		  src/protocols/gps.c \
		  src/protocols/http.c \
		  src/protocols/imap.c \
		  src/protocols/ldap2.c \
		  src/protocols/ldap3.c \
		  src/protocols/lmtp.c \
		  src/protocols/memcache.c \
		  src/protocols/mongodb.c \
		  src/protocols/mqtt.c \
		  src/protocols/mysql.c \
		  src/protocols/nntp.c \
		  src/protocols/ntp3.c \
		  src/protocols/pgsql.c \
		  src/protocols/pop.c \
		  src/protocols/postfix_policy.c \
		  src/protocols/protocol.c \
		  src/protocols/radius.c \
		  src/protocols/rdate.c \
		  src/protocols/redis.c \
		  src/protocols/rsync.c \
		  src/protocols/sieve.c \
		  src/protocols/sip.c \
		  src/protocols/smtp.c \
		  src/protocols/spamassassin.c \
		  src/protocols/ssh.c \
		  src/protocols/tns.c \
		  src/protocols/websocket.c \
		  src/ssl/Ssl.c \
		  src/terminal/TextBox.c \
		  src/terminal/TextColor.c \
                  src/statistics/Statistics.c

monit_LDADD 	= libmonit/libmonit.la
monit_LDFLAGS 	= -static $(EXTLDFLAGS)

man_MANS 	= monit.1

BUILT_SOURCES   = src/lex.yy.c src/y.tab.c src/y.tab.h

CLEANFILES	= src/y.output
DISTCLEANFILES	= *~ $(BUILT_SOURCES)

define check-exit
|| exit 1

endef

# -------
# Targets
# -------

dist-hook::
	-rm -rf `find $(distdir) -name "._*"`
	-rm -rf `find $(distdir) -name ".DS_Store"`
	-rm -rf `find $(distdir) -name ".libs"`
	-rm -rf `find $(distdir) -name ".git"`
	-rm -rf `find $(distdir) -name ".dirstamp"`
	-rm -rf $(distdir)/libmonit/libmonit.xcodeproj
	-rm -rf $(distdir)/libmonit/config.log
	-rm -rf $(distdir)/libmonit/config.status
	-rm -rf $(distdir)/libmonit/autom4te.cache
	-rm -f $(distdir)/src/config.h
	-rm -f $(distdir)/src/stamp-*
	-rm -f $(distdir)/src/y.output
	-rm -f $(distdir)/README.md
	-rm -f $(distdir)/libmonit/README*
	-mv $(distdir)/doc/CHANGES $(distdir)/
	-perl -pi -e 's/^Version: .*/Version: '$(VERSION)'/' $(distdir)/system/packages/redhat/monit.spec
	-chmod 600 monitrc

clean-local:
	-rm -f `find . -name "*.o" -o -name "*.lo" -o -name "*.loT" -o -name "*~"`

distclean-local:
	-rm -rf autom4te.cache/
	-rm -f monit-[0-9].*tar.gz

cleanall: clean distclean
	-git clean -fxd

monit.1: doc/monit.pod
	$(POD2MAN) $(POD2MANFLAGS) $< > $@
	-rm -f pod2*


# -------------
# Grammar rules
# -------------

src/y.tab.c src/y.tab.h: run-yacc
	
.INTERMEDIATE: run-yacc
run-yacc: src/p.y
	$(YACC) $(YACCFLAGS) -o src/y.tab.c $<

src/lex.yy.c: src/l.l
	$(FLEX) $(FLEXFLAGS) -o$@ $<


# --------------
# MacOS codesign
# --------------
if WITH_CODESIGN
monit_LDFLAGS   += -sectcreate __TEXT __info_plist config/Info.plist
all-local: $(bin_PROGRAMS)
	$(foreach file, $(bin_PROGRAMS), \
                codesign -s $(CODESIGN_IDENTITY) -v --deep --timestamp --options runtime $(file) \
        $(check-exit))
endif
