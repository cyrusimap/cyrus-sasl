# Makefile.am for the SASL library
# Rob Earhart
# $Id: Makefile.am,v 1.40 2001/02/19 19:30:04 leg Exp $
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

# Library version info - here at the top, for sanity
sasl_version = 8:10:1

INCLUDES=-I$(top_srcdir)/include

EXTRA_DIST = saslint.h windlopen.c

lib_LTLIBRARIES = libsasl.la

libsasl_la_SOURCES = common.c saslutil.c server.c client.c md5.c dlopen.c checkpw.c config.c
EXTRA_libsasl_la_SOURCES = db_none.c db_ndbm.c db_gdbm.c db_berkeley.c db_testw32.c
libsasl_la_LDFLAGS = -version-info $(sasl_version)
libsasl_la_DEPENDENCIES = $(SASL_DB_BACKEND) @LTLIBOBJS@
libsasl_la_LIBADD = @LTLIBOBJS@ $(SASL_DB_BACKEND) $(SASL_DB_LIB) $(SASL_DL_LIB) $(PLAIN_LIBS) $(GSSAPIBASE_LIBS) $(GSSAPI_LIBS) $(LIB_SOCKET)
# PLAIN_LIBS are linked in for sasl_checkpass
