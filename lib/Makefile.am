# Makefile.am for the SASL library
# Rob Earhart
# $Id: Makefile.am,v 1.5 1998/11/17 04:18:35 rob Exp $
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
sasl_version = 2:0:0

INCLUDES=-I$(top_srcdir)/include

EXTRA_DIST = saslint.h makedbm.c

EXTRA_PROGRAMS = test
test_LDADD = libsasl.la

lib_LTLIBRARIES = libsasl.la

libsasl_la_SOURCES = common.c saslutil.c server.c client.c md5.c dlopen.c
libsasl_la_LDFLAGS = -version-info $(sasl_version)
libsasl_la_LIBADD = $(SASL_DB_LIB) $(SASL_DL_LIB)
