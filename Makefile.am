# Top-level Makefile.am for SASL
# Rob Earhart
# $Id: Makefile.am,v 1.9 1999/01/12 22:11:55 rob Exp $
#
################################################################
#        Copyright 1998 by Carnegie Mellon University
#
#                      All Rights Reserved
#
#Permission to use, copy, modify, and distribute this software and its
#documentation for any purpose and without fee is hereby granted,
#provided that the above copyright notice appear in all copies and that
#both that copyright notice and this permission notice appear in
#supporting documentation, and that the name of Carnegie Mellon University
#not be used in advertising or publicity pertaining to distribution of the
#software without specific, written prior permission.
#
#CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
#SOFTWARE, INCLUDING #ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
#IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR ANY SPECIAL,
#INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
#LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
#OR OTHER TORTIOUS ACTION, #ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#PERFORMANCE OF THIS SOFTWARE.
################################################################

SUBDIRS=include lib plugins utils @DIRS@

dist-hook:
	cp -r -p $(srcdir)/config $(srcdir)/win32 $(distdir)
	find $(distdir) -name CVS -print | xargs rm -rf

install-exec-local:
	@if test "$(plugindir)" != "$(prefix)/lib/sasl"; then \
	  echo "********************************************************"; \
	  echo "* WARNING:";			\
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
