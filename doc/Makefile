# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.4 from Makefile.am

# Copyright (C) 1994, 1995-8, 1999 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

# Makefile.am for SASL documentation
# Rob Earhart
# $Id: Makefile,v 1.1 2001/12/04 17:46:41 rjs3 Exp $
#
################################################################
# Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer. 
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# 3. The name "Carnegie Mellon University" must not be used to
#    endorse or promote products derived from this software without
#    prior written permission. For permission or any other legal
#    details, please contact  
#      Office of Technology Transfer
#      Carnegie Mellon University
#      5000 Forbes Avenue
#      Pittsburgh, PA  15213-3890
#      (412) 268-4387, fax: (412) 268-7395
#      tech-transfer@andrew.cmu.edu
#
# 4. Redistributions of any form whatsoever must retain the following
#    acknowledgment:
#    "This product includes software developed by Computing Services
#     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
#
# CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
# THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
# FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
# OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
################################################################


SHELL = /bin/sh

srcdir = .
top_srcdir = ..
prefix = /usr/local
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${prefix}/share
sysconfdir = ${prefix}/etc
sharedstatedir = ${prefix}/com
localstatedir = ${prefix}/var
libdir = ${exec_prefix}/lib
infodir = ${prefix}/info
mandir = ${prefix}/man
includedir = ${prefix}/include
oldincludedir = /usr/include

DESTDIR =

pkgdatadir = $(datadir)/cyrus-sasl
pkglibdir = $(libdir)/cyrus-sasl
pkgincludedir = $(includedir)/cyrus-sasl

top_builddir = ..

ACLOCAL = aclocal -I $(top_srcdir)/cmulocal -I $(top_srcdir)/config
AUTOCONF = autoconf
AUTOMAKE = automake
AUTOHEADER = autoheader

INSTALL = /usr/local/bin/install -c
INSTALL_PROGRAM = ${INSTALL} $(AM_INSTALL_PROGRAM_FLAGS)
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
transform = s,x,x,

NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
host_alias = i686-pc-linux-gnu
host_triplet = i686-pc-linux-gnu
AS = @AS@
AWK = gawk
CC = gcc
CPP = gcc -E
DIRS = 
DLLTOOL = @DLLTOOL@
DMALLOC_LIBS = 
GETADDRINFOOBJS = 
GETNAMEINFOOBJS = 
GETSUBOPT = 
GSSAPIBASE_LIBS =  -lgssapi -lkrb5 -ldes -lasn1 -lroken  -lcom_err -lndbm -lresolv
GSSAPI_LIBS = 
JAVAC = javac
JAVADOC = javadoc
JAVAH = javah
JAVAROOT = ..
JAVA_INCLUDES =  -I/usr/local/include -I/usr/local/include/DPS -I/usr/local/include/afs -I/usr/local/include/X11 -I/usr/local/include/X11/ICE -I/usr/local/include/X11/PEX5 -I/usr/local/include/X11/PM -I/usr/local/include/X11/SM -I/usr/local/include/X11/Xaw -I/usr/local/include/X11/Xmu -I/usr/local/include/X11/X11 -I/usr/local/include/X11/Xaw3d -I/usr/local/include/X11/bitmaps -I/usr/local/include/X11/extensions -I/usr/local/include/X11/fonts -I/usr/local/include/X11/fonts/codeconv -I/usr/local/include/X11/pixmaps -I/usr/local/include/X11/pixmaps/pixmaps -I/usr/local/include/X11/pixmaps/pixmaps/xpm3icons -I/usr/local/include/X11/pixmaps/xpm3icons -I/usr/local/include/X11/Xft -I/usr/local/include/Xm -I/usr/local/include/GL -I/usr/local/include/kpathsea -I/usr/local/include/java -I/usr/local/include/java/linux -I/usr/local/include/maple -I/usr/local/include/Mesa-3.0 -I/usr/local/include/Mesa-3.0/GL -I/usr/local/include/Mrm -I/usr/local/include/sasl -I/usr/local/include/ams -I/usr/local/include/atk -I/usr/local/include/readline -I/usr/local/include/cyrus -I/usr/local/include/IIOP -I/usr/local/include/ORBitutil -I/usr/local/include/depot -I/usr/local/include/ss -I/usr/local/include/g++-3 -I/usr/local/include/g++-3/std -I/usr/local/include/rx -I/usr/local/include/libnet -I/usr/local/include/mysql -I/usr/local/include/openssl -I/usr/local/include/kadm5 -I/usr/local/include/pgsql -I/usr/local/include/pgsql/lib -I/usr/local/include/pgsql/libpq -I/usr/local/include/pgsql/libpq++ -I/usr/local/include/sfio -I/usr/local/include/snap3 -I/usr/local/include/SDL -I/usr/local/include/gck -I/usr/local/include/stage -I/usr/local/include/uil -I/usr/local/include/zephyr -I/usr/local/include/imap -I/usr/local/include/zip -I/usr/local/include/ORBitservices -I/usr/local/include/gconf -I/usr/local/include/orb -I/usr/local/include/gdk-pixbuf -I/usr/local/include/gnome-xml -I/usr/local/include/xmms -I/usr/local/include/gimp-print -I/usr/local/include/glade -I/usr/local/include/glib-1.2 -I/usr/local/include/glibtop -I/usr/local/include/zvt -I/usr/local/include/gtk-1.2 -I/usr/local/include/gtk-1.2/gdk -I/usr/local/include/gtk-1.2/gtk -I/usr/local/include/gtk-xmhtml -I/usr/local/include/libIDL -I/usr/local/include/libart_lgpl -I/usr/local/include/libgimp -I/usr/local/include/libgnome -I/usr/local/include/libgnomeui -I/usr/local/include/libgnomevfs -I/usr/local/include/libgnorba -I/usr/local/include/ucd-snmp -I/usr/local/include/liboaf -I/usr/local/include/freetype2 -I/usr/local/include/freetype2/freetype -I/usr/local/include/freetype2/freetype/config -I/usr/local/include/freetype2/freetype/cache -I/usr/local/include/freetype2/freetype/internal -I/usr/local/include/libxml -I/include
LIBOBJS = 
LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIB_CRYPT = -lcrypt
LIB_DES = -ldes
LIB_PAM = 
LIB_SASL = @LIB_SASL@
LIB_SOCKET = -lresolv 
LN_S = ln -s
LTGETADDRINFOOBJS = 
LTGETNAMEINFOOBJS = 
LTLIBOBJS = 
LTSNPRINTFOBJS = 
MAKEINFO = makeinfo
NM = /usr/bin/nm -B
OBJDUMP = @OBJDUMP@
OTP_LIBS = 
PACKAGE = cyrus-sasl
PLAIN_LIBS = -lcrypt
PURECOV = 
PURIFY = 
PWCHECKMETH = 
RANLIB = ranlib
SASLFLAGS = @SASLFLAGS@
SASL_DB_BACKEND = db_berkeley.lo
SASL_DB_BACKEND_STATIC = ../sasldb/db_berkeley.o ../sasldb/allockey.o
SASL_DB_INC = 
SASL_DB_LIB =  -ldb-3.1
SASL_DB_MANS = saslpasswd2.8 sasldblistusers2.8
SASL_DB_UTILS = saslpasswd2 sasldblistusers2
SASL_DL_LIB = -ldl
SASL_KRB_LIB = -lkrb -ldes -lcom_err
SASL_MECHS =  libsasldb.la libcrammd5.la libdigestmd5.la libotp.la libkerberos4.la libgssapiv2.la libplain.la libanonymous.la liblogin.la
SASL_STATIC_LIBS =  libsasl2.a
SASL_STATIC_OBJS =  ../plugins/sasldb.o ../plugins/cram.o ../plugins/digestmd5.o ../plugins/otp.o ../plugins/kerberos4.o ../plugins/gssapi.o ../plugins/plain.o ../plugins/anonymous.o ../plugins/login.o ../plugins/plugin_common.o
SASL_UTIL_HEADERS_EXTRA = sfsasl.h
SASL_UTIL_LIBS_EXTRA = libsfsasl2.la
SFIO_INC_FLAGS = -I/usr/local/include/sfio
SFIO_LIB_FLAGS = -L/usr/local/lib/sfio -lsfio
SMTPTEST_PROGRAM = smtptest
SNPRINTFOBJS = 
SRP_LIBS = 
VERSION = 2.0.4-BETA
plugindir = /usr/local/lib/sasl2

EXTRA_DIST = rfc1321.txt 		rfc1939.txt 		rfc2104.txt 		rfc2195.txt 		rfc2222.txt 		rfc2243.txt 		rfc2245.txt 		rfc2289.txt 		rfc2444.txt 		rfc2595.txt 		rfc2831.txt 		rfc2945.txt 		rfc3174.txt 		draft-burdis-cat-srp-sasl-05.txt 		draft-ietf-cat-sasl-gssapi-05.txt 		draft-myers-saslrev-01.txt 		draft-sasl-login.txt 		programming.html 		sysadmin.html 		gssapi.html 		advanced.html 		options.html 		plugprog.html 		appconvert.html 		macosx.html 		index.html 

mkinstalldirs = $(SHELL) $(top_srcdir)/config/mkinstalldirs
CONFIG_HEADER = ../config.h
CONFIG_CLEAN_FILES = 
DIST_COMMON =  Makefile.am Makefile.in


DISTFILES = $(DIST_COMMON) $(SOURCES) $(HEADERS) $(TEXINFOS) $(EXTRA_DIST)

TAR = gtar
GZIP_ENV = --best
all: all-redirect
.SUFFIXES:
$(srcdir)/Makefile.in: Makefile.am $(top_srcdir)/configure.in $(ACLOCAL_M4) 
	cd $(top_srcdir) && $(AUTOMAKE) --gnu --include-deps doc/Makefile

Makefile: $(srcdir)/Makefile.in  $(top_builddir)/config.status
	cd $(top_builddir) \
	  && CONFIG_FILES=$(subdir)/$@ CONFIG_HEADERS= $(SHELL) ./config.status

tags: TAGS
TAGS:


distdir = $(top_builddir)/$(PACKAGE)-$(VERSION)/$(subdir)

subdir = doc

distdir: $(DISTFILES)
	@for file in $(DISTFILES); do \
	  d=$(srcdir); \
	  if test -d $$d/$$file; then \
	    cp -pr $$d/$$file $(distdir)/$$file; \
	  else \
	    test -f $(distdir)/$$file \
	    || ln $$d/$$file $(distdir)/$$file 2> /dev/null \
	    || cp -p $$d/$$file $(distdir)/$$file || :; \
	  fi; \
	done
info-am:
info: info-am
dvi-am:
dvi: dvi-am
check-am: all-am
check: check-am
installcheck-am:
installcheck: installcheck-am
install-exec-am:
install-exec: install-exec-am

install-data-am:
install-data: install-data-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am
install: install-am
uninstall-am:
uninstall: uninstall-am
all-am: Makefile
all-redirect: all-am
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) AM_INSTALL_PROGRAM_FLAGS=-s install
installdirs:


mostlyclean-generic:

clean-generic:

distclean-generic:
	-rm -f Makefile $(CONFIG_CLEAN_FILES)
	-rm -f config.cache config.log stamp-h stamp-h[0-9]*

maintainer-clean-generic:
mostlyclean-am:  mostlyclean-generic

mostlyclean: mostlyclean-am

clean-am:  clean-generic mostlyclean-am

clean: clean-am

distclean-am:  distclean-generic clean-am
	-rm -f libtool

distclean: distclean-am

maintainer-clean-am:  maintainer-clean-generic distclean-am
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

maintainer-clean: maintainer-clean-am

.PHONY: tags distdir info-am info dvi-am dvi check check-am \
installcheck-am installcheck install-exec-am install-exec \
install-data-am install-data install-am install uninstall-am uninstall \
all-redirect all-am all installdirs mostlyclean-generic \
distclean-generic clean-generic maintainer-clean-generic clean \
mostlyclean distclean maintainer-clean


# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
