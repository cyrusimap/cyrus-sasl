sbin_PROGRAMS	= saslauthd

saslauthd_SOURCES = saslauthd.c mechanisms.c globals.h mechanisms.h auth_dce.c auth_dce.h auth_getpwent.c auth_getpwent.h auth_krb5.c auth_krb5.h auth_krb4.c auth_krb4.h auth_pam.c auth_pam.h auth_rimap.c auth_rimap.h auth_shadow.c auth_shadow.h auth_sia.c auth_sia.h
saslauthd_LDADD	= @SASL_KRB_LIB@ @GSSAPIBASE_LIBS@ @GSSAPI_LIBS@ @PLAIN_LIBS@ @LIB_SOCKET@

EXTRA_DIST	= saslauthd.8
INCLUDES	= -I$(top_srcdir)/include

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(mandir)/cat8
	$(INSTALL_DATA) saslauthd.8 $(mandir)/cat8/saslauthd.8
