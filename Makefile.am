# Top-level Makefile.am for SASL
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

SUBDIRS=include lib plugins utils doc man @DIRS@

dist-hook:
	@for dir in config cmulocal sample win32 pwcheck; do	\
	  if test ! -d $(distdir)/$$dir; then			\
	    (set -x; cp -r -p $(top_srcdir)/$$dir $(distdir));	\
	  fi;							\
	done
	@find $(distdir) -name CVS -print | xargs -t rm -rf

install-exec-local:
	@if test "$(plugindir)" != "$(prefix)/lib/sasl"; then \
	  echo "********************************************************"; \
	  echo "* WARNING:"; \
	  echo "* Plugins are being installed into $(prefix)/lib/sasl,"; \
	  echo "* but the library will look for them in $(plugindir)."; \
	  echo "* You need to make sure that the plugins will eventually"; \
	  echo "* be in $(plugindir) -- the easiest way is to make a"; \
	  echo "* symbolic link from $(plugindir) to $(prefix)/lib/sasl,"; \
	  echo "* but this may not be appropriate for your site, so this"; \
	  echo "* installation procedure won't do it for you."; \
	  echo "*"; \
          echo "* If you don't want to do this for some reason, you can"; \
          echo "* set the location where the library will look for plugins"; \
	  echo "* by setting the environment variable SASL_PATH to the path"; \
	  echo "* the library should use."; \
	  echo "********************************************************"; \
	fi
