sbin_PROGRAMS	= saslauthd
EXTRA_PROGRAMS  = testsaslauthd

saslauthd_SOURCES = mechanisms.c globals.h \
		    mechanisms.h auth_dce.c auth_dce.h auth_getpwent.c \
		    auth_getpwent.h auth_krb5.c auth_krb5.h auth_krb4.c \
		    auth_krb4.h auth_pam.c auth_pam.h auth_rimap.c \
		    auth_rimap.h auth_shadow.c auth_shadow.h auth_sia.c \
		    auth_sia.h auth_sasldb.c auth_sasldb.h lak.c lak.h \
		    auth_ldap.c auth_ldap.h
EXTRA_saslauthd_sourced = saslauthd-unix.c saslauthd-doors.c getaddrinfo.c \
			  getnameinfo.c
saslauthd_DEPENDENCIES = @COMPAT_OBJ@
saslauthd_LDADD	= @COMPAT_OBJ@ @SASL_KRB_LIB@ @GSSAPIBASE_LIBS@ \
		  @GSSAPI_LIBS@ @PLAIN_LIBS@ @LIB_SIA@ @LIB_SOCKET@ \
		  @SASL_DB_LIB@ @LIB_PAM@ @LDAP_LIBS@

testsaslauthd_SOURCES = testsaslauthd.c
testsaslauthd_DEPENDENCIES = @COMPAT_OBJ@
testsaslauthd_LDADD = @COMPAT_OBJ@ @LIB_SOCKET@

EXTRA_DIST	= saslauthd.8 saslauthd.mdoc config include \
		  getnameinfo.c getaddrinfo.c saslauthd-unix.c \
		  saslauthd-doors.c LDAP_SASLAUTHD
INCLUDES	= -I$(top_srcdir)/include
DEFS            = @DEFS@ -DSASLAUTHD_CONF_FILE_DEFAULT=\"@sysconfdir@/saslauthd.conf\" -I. -I$(srcdir) -I..


dist-hook: saslauthd.8

saslauthd.8: saslauthd.mdoc
	nroff -mdoc $(srcdir)/saslauthd.mdoc > $(srcdir)/saslauthd.8

install-data-local: saslauthd.8
	$(mkinstalldirs) $(DESTDIR)$(mandir)/cat8
	$(INSTALL_DATA) $(srcdir)/saslauthd.8 $(DESTDIR)$(mandir)/cat8/saslauthd.8
