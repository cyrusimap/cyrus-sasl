# Makefile.am for the Java SASL library
# Rob Earhart
# $Id: Makefile.am,v 1.2 1998/11/16 20:23:37 rob Exp $
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
#OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
#PERFORMANCE OF THIS SOFTWARE.
################################################################

javasasl_version = 0:0:0

javasasldir = $(prefix)/lib/java/classes/sasl
javahtmldir = $(prefix)/html/sasl

INCLUDES=$(JAVA_INCLUDES) -I$(top_srcdir)/include

CLASSES = BadAuthException.class GenericException.class InteractException.class NoMechException.class NotDoneException.class saslClientConn.class saslClientFactory.class saslCommonConn.class saslException.class saslFilterInputStream.class saslFilterOutputStream.class saslPrompt.class saslServerConn.class saslServerFactory.class saslUtils.class

lib_LTLIBRARIES = libjavasasl.la
libjavasasl_la_SOURCES = javasasl.c
libjavasasl_la_LDFLAGS = -export_dynamic -version-info $(javasasl_version) $(wildcard ../lib/*.lo)

javasasl.c: javasasl.h

javasasl.h: $(CLASSES)
	$(CLASSPATH_ENV) $(JAVAH) -o $@ -jni $(patsubst %.class,sasl.%,$^)

${CLASSES}: classjavasasl.stamp

javasasl_JAVA = BadAuthException.java GenericException.java InteractException.java NoMechException.java NotDoneException.java saslClientConn.java saslClientFactory.java saslCommonConn.java saslException.java saslFilterInputStream.java saslFilterOutputStream.java saslMechList.java saslPrompt.java saslServerConn.java saslServerFactory.java saslUtils.java

install-data-local:
	$(mkinstalldirs) $(javahtmldir)
	$(CLASSPATH_ENV) $(JAVADOC) -d $(javahtmldir) sasl
