sbin_PROGRAMS	= saslauthd
man_MANS	= saslauthd.8

saslauthd_SOURCES = saslauthd.c mechanisms.c globals.h mechanisms.h auth_dce.c auth_dce.h auth_getpwent.c auth_getpwent.h auth_krb4.c auth_krb4.h auth_pam.c auth_pam.h auth_rimap.c auth_rimap.h auth_shadow.c auth_shadow.h auth_sia.c auth_sia.h
saslauthd_LDADD	= @SASL_KRB_LIB@

INCLUDES	= -I$(top_srcdir)/include
EXTRA_DIST	= saslauthd.8
