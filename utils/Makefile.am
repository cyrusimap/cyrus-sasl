# Makefile.am for the SASL utilities
# Rob Earhart
#
#         Copyright 1999 by Carnegie Mellon University
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

sbin_PROGRAMS = saslpasswd
man_MANS = saslpasswd.8
saslpasswd_LDADD = ../lib/libsasl.la

noinst_PROGRAMS = dbconverter-1.5.9
dbconverter_1_5_9_LDADD = ../lib/libsasl.la $(SASL_DB_LIB)

EXTRA_PROGRAMS = testsuite
testsuite_LDADD = ../lib/libsasl.la $(SASL_DB_LIB)

include_HEADERS = @SASL_UTIL_HEADERS_EXTRA@
EXTRA_HEADERS = sfsasl.h

lib_LTLIBRARIES = @SASL_UTIL_LIBS_EXTRA@
EXTRA_LTLIBRARIES = libsfsasl.la
libsfsasl_la_SOURCES = sfsasl.c
libsfsasl_la_LDFLAGS = -version-info 0:0:0 -export-dynamic -rpath $(libdir)

INCLUDES=-I$(top_srcdir)/include
EXTRA_DIST = saslpasswd.8 sfsasl.h dbconverter-1.5.5.c testsuite.c
