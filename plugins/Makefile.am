# Makefile.am for the SASL plugins
# Rob Earhart
#
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
# CURRENT:REVISION:AGE
plain_version = 1:15:0
anonymous_version = 1:16:0
kerberos4_version = 1:17:0
crammd5_version = 1:17:0
scrammd5_version = 1:7:0
gssapiv2_version = 1:18:0
digestmd5_version = 0:19:0
login_version = 0:6:0
srp_version = 0:1:0
# x509_version = 0:0:0

INCLUDES=-I$(top_srcdir)/include

LDFLAGS = @LDFLAGS@ -export-dynamic -rpath $(plugindir)

plugindir = @plugindir@

sasldir = $(prefix)/lib/sasl
sasl_LTLIBRARIES = @SASL_MECHS@
EXTRA_LTLIBRARIES = libplain.la libanonymous.la libkerberos4.la libcrammd5.la libscrammd5.la libgssapiv2.la libdigestmd5.la liblogin.la libsrp.la

libplain_la_SOURCES = plain.c
libplain_la_LDFLAGS = -version-info $(plain_version)
libplain_la_LIBADD = $(PLAIN_LIBS)

libanonymous_la_SOURCES = anonymous.c
libanonymous_la_LDFLAGS = -version-info $(anonymous_version)

libkerberos4_la_SOURCES = kerberos4.c
libkerberos4_la_LDFLAGS = -version-info $(kerberos4_version)
libkerberos4_la_LIBADD = $(SASL_KRB_LIB) $(LIB_SOCKET)

libgssapiv2_la_SOURCES = gssapi.c
libgssapiv2_la_LDFLAGS = -version-info $(gssapiv2_version)
libgssapiv2_la_LIBADD = $(GSSAPIBASE_LIBS) $(GSSAPI_LIBS) $(LIB_SOCKET)

libcrammd5_la_SOURCES = cram.c
libcrammd5_la_LDFLAGS = -version-info $(crammd5_version)

libscrammd5_la_SOURCES = scram.c
libscrammd5_la_LDFLAGS = -version-info $(scrammd5_version)

libdigestmd5_la_SOURCES = digestmd5.c
libdigestmd5_la_LDFLAGS = -version-info $(digestmd5_version)
libdigestmd5_la_LIBADD = $(LIB_DES) $(LIB_SOCKET)

liblogin_la_SOURCES = login.c
liblogin_la_LDFLAGS = -version-info $(login_version)
liblogin_la_LIBADD = $(PLAIN_LIBS)

libsrp_la_SOURCES = srp.c
libsrp_la_LDFLAGS = -version-info $(srp_version)
libsrp_la_LIBADD = $(SRP_LIBS)

# libx509_la_SOURCES = x509.c
# libx509_la_LDFLAGS = -version-info $(x509_version)
# libx509_la_LIBADD = $(X509_LIBS)
