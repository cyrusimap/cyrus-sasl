sbin_PROGRAMS	= saslauthd

EXTRA_DIST = getnameinfo.c getaddrinfo.c
saslauthd_SOURCES = saslauthd.c mechanisms.c globals.h mechanisms.h auth_dce.c auth_dce.h auth_getpwent.c auth_getpwent.h auth_krb5.c auth_krb5.h auth_krb4.c auth_krb4.h auth_pam.c auth_pam.h auth_rimap.c auth_rimap.h auth_shadow.c auth_shadow.h auth_sia.c auth_sia.h auth_sasldb.c auth_sasldb.h $(COMPAT_SRC)
saslauthd_DEPENDENCIES = @COMPAT_OBJ@
saslauthd_LDADD	= @COMPAT_OBJ@ @SASL_KRB_LIB@ @GSSAPIBASE_LIBS@ @GSSAPI_LIBS@ @PLAIN_LIBS@ @LIB_SIA@ @LIB_SOCKET@ @SASL_DB_LIB@ @LIB_PAM@

EXTRA_DIST	= saslauthd.8 config include
INCLUDES	= -I$(top_srcdir)/include

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(mandir)/cat8
	$(INSTALL_DATA) $(srcdir)/saslauthd.8 $(DESTDIR)$(mandir)/cat8/saslauthd.8
