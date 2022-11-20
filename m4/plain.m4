dnl Check for PLAIN (and therefore crypt)

AC_DEFUN([SASL_PLAIN_CHK],[

dnl PLAIN
 AC_ARG_ENABLE(plain, [  --enable-plain          enable PLAIN authentication [yes] ],
  plain=$enableval,
  plain=yes)

 AC_MSG_CHECKING(PLAIN)
 if test "$plain" != no; then
  AC_MSG_RESULT(enabled)
  SASL_MECHS="$SASL_MECHS libplain.la"
  if test "$enable_static" = yes; then
    SASL_STATIC_OBJS="$SASL_STATIC_OBJS plain.o"
    SASL_STATIC_SRCS="$SASL_STATIC_SRCS \$(top_srcdir)/plugins/plain.c"
    AC_DEFINE(STATIC_PLAIN,[],[Link PLAIN Staticly])
  fi
 else
  AC_MSG_RESULT(disabled)
 fi
])
