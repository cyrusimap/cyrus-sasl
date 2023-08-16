# Makefile.am for the SASL plugins
# Rob Siemborski
# Rob Earhart
# $Id: Makefile.am,v 1.86 2011/09/05 14:18:10 murch Exp $
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

# Library version info - here at the top, for sanity
# See <http://www.gnu.org/software/libtool/manual/libtool.html#Versioning>
# CURRENT:REVISION:AGE
plugin_version = 3:0:0

AM_CPPFLAGS=-DLIBSASL_EXPORTS=1 -I$(top_srcdir)/include -I$(top_srcdir)/lib -I$(top_srcdir)/sasldb -I$(top_srcdir)/common -I$(top_builddir)/include
AM_LDFLAGS = -module -export-dynamic -rpath $(libdir) -version-info $(plugin_version) -no-undefined

if BUILD_LIBOBJ
COMPAT_OBJS = $(top_builddir)/lib/libobj.la
endif
PLUGIN_COMMON_OBJS = $(top_builddir)/common/libplugin_common.la
CRYPTO_COMPAT_OBJS = $(top_builddir)/common/libcrypto_compat.la

EXTRA_DIST = makeinit.sh NTMakefile
noinst_SCRIPTS = makeinit.sh

LIB_MYSQL = @LIB_MYSQL@

if OPAQUE_INTERNAL
OPAQUE_INTERNAL_IMPL_SRC = opaque_impl.c
if INTERNAL_HKDF
OPAQUE_INTERNAL_IMPL_SRC += kdf_hkdf_sha512.c
endif
endif

plugindir = @plugindir@
plugin_LTLIBRARIES = @SASL_MECHS@

EXTRA_LTLIBRARIES = libplain.la libanonymous.la \
	libgs2.la libgssapiv2.la libsrp.la libotp.la \
	libscram.la libpassdss.la libsasldb.la libsql.la libldapdb.la libopaque.la

libplain_la_SOURCES = plain.c plain_init.c
libplain_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)
libplain_la_LIBADD = $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)

libanonymous_la_SOURCES = anonymous.c anonymous_init.c
libanonymous_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)
libanonymous_la_LIBADD = $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)

libgs2_la_SOURCES = gs2.c gs2_init.c gs2_token.c gs2_token.h
libgs2_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)
libgs2_la_LIBADD = $(GSSAPIBASE_LIBS) $(GSSAPI_LIBS) $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)

libgssapiv2_la_SOURCES = gssapi.c gssapiv2_init.c
libgssapiv2_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)
libgssapiv2_la_LIBADD = $(GSSAPIBASE_LIBS) $(GSSAPI_LIBS) $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)

libscram_la_SOURCES = scram.c scram_init.c
libscram_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)
libscram_la_LIBADD = $(SCRAM_LIBS) $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)

libsrp_la_SOURCES = srp.c srp_init.c
libsrp_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS) $(CRYPTO_COMPAT_OBJS)
libsrp_la_LIBADD = $(SRP_LIBS) $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS) $(CRYPTO_COMPAT_OBJS)

libopaque_la_SOURCES = opaque.c opaque_init.c $(OPAQUE_INTERNAL_IMPL_SRC)
libopaque_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS) $(CRYPTO_COMPAT_OBJS)
libopaque_la_LIBADD = $(OPAQUE_LIBS) $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS) $(CRYPTO_COMPAT_OBJS)

libotp_la_SOURCES = otp.c otp_init.c otp.h
libotp_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)
libotp_la_LIBADD = $(OTP_LIBS) $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)

libpassdss_la_SOURCES = passdss.c passdss_init.c
libpassdss_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS) $(CRYPTO_COMPAT_OBJS)
libpassdss_la_LIBADD = $(PASSDSS_LIBS) $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS) $(CRYPTO_COMPAT_OBJS)

# Auxprop Plugins
libsasldb_la_SOURCES = sasldb.c sasldb_init.c
libsasldb_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)
libsasldb_la_LIBADD = ../sasldb/$(SASL_DB_BACKEND) ../sasldb/allockey.lo $(SASL_DB_LIB) $(LIB_SOCKET) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)

libldapdb_la_SOURCES = ldapdb.c ldapdb_init.c
libldapdb_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)
libldapdb_la_LIBADD = $(LIB_LDAP) $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)

libsql_la_SOURCES = sql.c sql_init.c
libsql_la_LDFLAGS = $(LIB_MYSQL) $(LIB_PGSQL) $(LIB_SQLITE) $(LIB_SQLITE3) \
	$(AM_LDFLAGS)
libsql_la_DEPENDENCIES = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)
libsql_la_LIBADD = $(COMPAT_OBJS) $(PLUGIN_COMMON_OBJS)

# Instructions for making the _init files

init_src=anonymous_init.c scram_init.c gs2_init.c gssapiv2_init.c \
plain_init.c srp_init.c opaque_init.c otp_init.c \
passdss_init.c sasldb_init.c sql_init.c ldapdb_init.c


CLEANFILES=$(init_src)

${init_src}: $(srcdir)/makeinit.sh
	$(SHELL) $(srcdir)/makeinit.sh $@
