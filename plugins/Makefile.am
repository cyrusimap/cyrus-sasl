# Makefile.am for the SASL plugins
# Rob Earhart
# $Id: Makefile.am,v 1.1 1998/11/16 20:06:40 rob Exp $
#
#
#         Copyright 1998 by Carnegie Mellon University
#
#                       All Rights Reserved
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appear in all copies and that
# both that copyright notice and this permission notice appear in
# supporting documentation, and that the name of CMU not be
# used in advertising or publicity pertaining to distribution of the
# software without specific, written prior permission.
#
# CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
# ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
# CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
# ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
# ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
# SOFTWARE.
#

# Library version info - here at the top, for sanity
plain_version = 0:2:0
anonymous_version = 0:2:0
kerberos4_version = 0:3:0
crammd5_version = 0:3:0
scrammd5_version = 0:3:0
gssapiv2_version = 0:0:0

INCLUDES=-I$(top_srcdir)/include

plugindir = @plugindir@

sasldir = $(prefix)/lib/sasl
sasl_LTLIBRARIES = @SASL_MECHS@
EXTRA_LTLIBRARIES = libplain.la libanonymous.la libkerberos4.la libcrammd5.la libscrammd5.la libgssapiv2.la

libplain_la_SOURCES = plain.c
libplain_la_LDFLAGS = -export-dynamic -version-info $(plain_version) -rpath $(plugindir) $(LDFLAGS)

libanonymous_la_SOURCES = anonymous.c
libanonymous_la_LDFLAGS = -export-dynamic -version-info $(anonymous_version) -rpath $(plugindir) $(LDFLAGS)

libkerberos4_la_SOURCES = kerberos4.c
libkerberos4_la_LDFLAGS = -export-dynamic -version-info $(kerberos4_version) -rpath $(plugindir) $(LDFLAGS) -lkrb -ldes

libgssapiv2_la_SOURCES = gssapi.c
libgssapiv2_la_LDFLAGS = -export-dynamic -version-info $(gssapiv2_version) -rpath $(plugindir) $(LDFLAGS) $(GSSAPIBASE_LIBS) $(GSSAPI_LIBS)

libcrammd5_la_SOURCES = cram.c
libcrammd5_la_LDFLAGS = -export-dynamic -version-info $(crammd5_version) -rpath $(plugindir) $(LDFLAGS)

libscrammd5_la_SOURCES = scram.c
libscrammd5_la_LDFLAGS = -export-dynamic -version-info $(scrammd5_version) -rpath $(plugindir) $(LDFLAGS)
