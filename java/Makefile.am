# Makefile.am for the Java SASL library
# Rob Earhart
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

javasasl_version = 1:0:0

javasasldir = $(prefix)/lib/java/classes/sasl
javahtmldir = $(prefix)/html/sasl

INCLUDES=$(JAVA_INCLUDES) -I$(top_srcdir)/include

javasasl_JAVA = CyrusSasl/Sasl.java CyrusSasl/GenericClient.java CyrusSasl/ClientFactory.java \
	        CyrusSasl/GenericCommon.java CyrusSasl/SaslClient.java \
	        CyrusSasl/SaslClientFactory.java CyrusSasl/SaslException.java \
	        CyrusSasl/SaslInputStream.java CyrusSasl/SaslOutputStream.java\
		CyrusSasl/SaslUtils.java

CLASSES = $(javasasl_JAVA:.java=.class)

lib_LTLIBRARIES = libjavasasl.la
libjavasasl_la_SOURCES = javasasl.c
libjavasasl_la_LDFLAGS = -export_dynamic -lsasl -version-info $(javasasl_version) $(wildcard ../lib/*.lo)

javasasl.c: javasasl.h

javasasl.h: $(CLASSES)
	$(CLASSPATH_ENV) $(JAVAH) -o $@ -jni $(patsubst CyrusSasl/%.class,CyrusSasl.%,$^)

${CLASSES}: classjavasasl.stamp

install-data-local:
	$(mkinstalldirs) $(javahtmldir)
	$(CLASSPATH_ENV) $(JAVADOC) -d $(javahtmldir) sasl
	-if test ! -h $(javahtmldir)/images; \
	then \
	  $(LN_S) $(JAVA_BASE)/docs/api/images $(javahtmldir)/images; \
	fi
