# Makefile.am for the SASL library
# Rob Earhart
# $Id: Makefile.am,v 1.25 1999/12/02 20:10:30 leg Exp $
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
sasl_version = 7:3:0

INCLUDES=-I$(top_srcdir)/include

EXTRA_DIST = saslint.h windlopen.c

lib_LTLIBRARIES = libsasl.la

libsasl_la_SOURCES = common.c saslutil.c server.c client.c md5.c dlopen.c checkpw.c config.c
EXTRA_libsasl_la_SOURCES = db_none.c db_ndbm.c db_gdbm.c db_berkeley.c db_testw32.c
libsasl_la_LDFLAGS = -version-info $(sasl_version)
libsasl_la_DEPENDENCIES = $(SASL_DB_BACKEND) @LTLIBOBJS@
libsasl_la_LIBADD = @LTLIBOBJS@ $(SASL_DB_BACKEND) $(SASL_DB_LIB) $(SASL_DL_LIB) $(PLAIN_LIBS)
# PLAIN_LIBS are linked in for sasl_checkpass
