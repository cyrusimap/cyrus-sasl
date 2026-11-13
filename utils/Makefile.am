# Makefile.am for the SASL utilities
# Rob Earhart
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

all_sasl_libs = ../lib/libsasl2.la $(SASL_DB_LIB) $(LIB_SOCKET) -lcrypto
all_sasl_static_libs = ../lib/.libs/libsasl2.a $(SASL_DB_LIB) $(LIB_SOCKET) $(GSSAPIBASE_LIBS) $(GSSAPI_LIBS) $(PLAIN_LIBS) $(SRP_LIBS) $(LIB_MYSQL) $(LIB_PGSQL) $(LIB_SQLITE3) -lcrypto

sbin_PROGRAMS = @SASL_DB_UTILS@ pluginviewer
EXTRA_PROGRAMS = saslpasswd2 sasldblistusers2 testsuite testsuitestatic pluginviewer

man_MANS = $(SASL_DB_MANS) pluginviewer.8

saslpasswd2_LDADD = ../sasldb/libsasldb.la $(all_sasl_libs)
saslpasswd2_SOURCES = saslpasswd.c
saslpasswd2_LDFLAGS = -rpath $(libdir)
sasldblistusers2_LDADD = ../sasldb/libsasldb.la $(all_sasl_libs)
sasldblistusers2_SOURCES = sasldblistusers.c
sasldblistusers2_LDFLAGS = -rpath $(libdir)
pluginviewer_LDADD = $(all_sasl_libs)
pluginviewer_SOURCES = pluginviewer.c
pluginviewer_LDFLAGS = -rpath $(libdir)

testsuite_LDADD = $(all_sasl_libs)

CLEANFILES=$(EXTRA_PROGRAMS)

testsuitestatic_SOURCES = testsuite.c
testsuitestatic_LDADD = $(all_sasl_static_libs) @SASL_DL_LIB@
testsuitestatic_DEPENDENCIES = ../lib/.libs/libsasl2.a

AM_CPPFLAGS=-DLIBSASL_EXPORTS=1 -I$(top_srcdir)/include -I$(top_builddir)/include @SASL_DB_INC@

EXTRA_DIST = saslpasswd2.8 sasldblistusers2.8 sasltestsuite.8 pluginviewer.8 testsuite.c pluginviewer.c NTMakefile
