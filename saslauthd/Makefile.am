sbin_PROGRAMS	= saslauthd
man_MANS	= saslauthd.8

saslauthd_SOURCES = saslauthd.c mechanisms.c auth_dce.c auth_getpwent.c auth_krb4.c auth_rimap.c auth_shadow.c auth_sia.c
saslauthd_LDADD	= @SASL_KRB_LIB@

INCLUDES	= -I$(top_srcdir)/include
EXTRA_DIST	= saslauthd.8