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

sbin_PROGRAMS = saslpasswd sasldblistusers
man_MANS = saslpasswd.8 sasldblistusers.8
saslpasswd_LDADD = ../lib/libsasl.la
sasldblistusers_LDADD = $(SASL_DB_LIB)

noinst_PROGRAMS = dbconverter-1.5.9
dbconverter_1_5_9_LDADD = ../lib/libsasl.la $(SASL_DB_LIB)

EXTRA_PROGRAMS = testsuite
testsuite_LDADD = ../lib/libsasl.la $(SASL_DB_LIB) $(LIB_SOCKET)

include_HEADERS = @SASL_UTIL_HEADERS_EXTRA@
EXTRA_HEADERS = sfsasl.h

lib_LTLIBRARIES = @SASL_UTIL_LIBS_EXTRA@
EXTRA_LTLIBRARIES = libsfsasl.la
libsfsasl_la_SOURCES = sfsasl.c
libsfsasl_la_LDFLAGS = -version-info 0:0:0 -export-dynamic -rpath $(libdir)

INCLUDES=-I$(top_srcdir)/include
EXTRA_DIST = saslpasswd.8 sasldblistusers.8 sfsasl.h dbconverter-1.5.5.c testsuite.c
