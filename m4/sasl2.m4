# sasl2.m4--sasl2 libraries and includes
# Rob Siemborski

# SASL_GSSAPI_CHK
# ---------------
AC_DEFUN([SASL_GSSAPI_CHK],
[AC_REQUIRE([SASL2_CRYPT_CHK])
AC_REQUIRE([CMU_SOCKETS])
AC_ARG_ENABLE([gssapi],
              [AC_HELP_STRING([--enable-gssapi=<DIR>],
                              [enable GSSAPI authentication [yes]])],
              [gssapi=$enableval],
              [gssapi=yes])
AC_ARG_WITH([gss_impl],
            [AC_HELP_STRING([--with-gss_impl={heimdal|mit|cybersafe|seam|auto}],
                            [choose specific GSSAPI implementation [[auto]]])],
            [gss_impl=$withval],
            [gss_impl=auto])

gs2="no"
if test "$gssapi" != no; then
  platform=
  case "${host}" in
    *-*-linux*)
      platform=__linux
      ;;
    *-*-hpux*)
      platform=__hpux
      ;;
    *-*-irix*)
      platform=__irix
      ;;
    *-*-solaris2*)
# When should we use __sunos?
      platform=__solaris
      ;;
    *-*-aix*)
###_AIX
      platform=__aix
      ;;
    *-*-darwin*)
      platform=__darwin
      ;;
    *)
      AC_WARN([The system type is not recognized. If you believe that CyberSafe GSSAPI works on this platform, please update the configure script])
      if test "$gss_impl" = "cybersafe"; then
        AC_MSG_ERROR([CyberSafe was forced, cannot continue as platform is not supported])
      fi
      ;;
  esac

  cmu_saved_CPPFLAGS=$CPPFLAGS

  if test -d ${gssapi}; then
    CPPFLAGS="$CPPFLAGS -I$gssapi/include"
# We want to keep -I in our CPPFLAGS, but only if we succeed
    cmu_saved_CPPFLAGS=$CPPFLAGS
### I am not sure how useful is this (and whether this is required at all
### especially when we have to provide two -L flags for new CyberSafe
    LDFLAGS="$LDFLAGS -L$gssapi/lib"

    if test -n "$platform"; then
      if test "$gss_impl" = "auto" -o "$gss_impl" = "cybersafe"; then
        CPPFLAGS="$CPPFLAGS -D$platform"
        if test -d "${gssapi}/appsec-sdk/include"; then
          CPPFLAGS="$CPPFLAGS -I${gssapi}/appsec-sdk/include"
        fi
      fi
    fi
  fi
  AC_CHECK_HEADER([gssapi.h],,
                  [AC_CHECK_HEADER([gssapi/gssapi.h],, [gssapi=no])])
  AC_CHECK_HEADERS(gssapi/gssapi_ext.h)
  CPPFLAGS=$cmu_saved_CPPFLAGS

fi

if test "$gssapi" != no; then
  if test "$ac_cv_header_gssapi_h" = "yes"; then
    AC_DEFINE(HAVE_GSSAPI_H,,[Define if you have the gssapi.h header file])
  elif test "$ac_cv_header_gssapi_gssapi_h" = "yes"; then
    AC_DEFINE(HAVE_GSSAPI_GSSAPI_H,,[Define if you have the gssapi/gssapi.h header file])
  fi

  # We need to find out which gssapi implementation we are
  # using. Supported alternatives are: MIT Kerberos 5,
  # Heimdal Kerberos 5 (http://www.pdc.kth.se/heimdal),
  # CyberSafe Kerberos 5 (http://www.cybersafe.com/)
  # and Sun SEAM (http://wwws.sun.com/software/security/kerberos/)
  #
  # The choice is reflected in GSSAPIBASE_LIBS

  AC_CHECK_LIB(resolv,res_search)
  if test -d ${gssapi}; then
     gssapi_dir="${gssapi}/lib"
     GSSAPIBASE_LIBS="-L$gssapi_dir"
     GSSAPIBASE_STATIC_LIBS="-L$gssapi_dir"
  else
     # FIXME: This is only used for building cyrus, and then only as
     # a real hack.  it needs to be fixed.
     gssapi_dir="/usr/local/lib"
  fi

  # Check a full link against the Heimdal libraries.
  # If this fails, check a full link against the MIT libraries.
  # If this fails, check a full link against the CyberSafe libraries.
  # If this fails, check a full link against the Solaris 8 and up libgss.

  if test "$gss_impl" = "auto" -o "$gss_impl" = "heimdal"; then
    gss_failed=0
    AC_CHECK_LIB(gssapi,gss_unwrap,gss_impl="heimdal",gss_failed=1,
                 ${GSSAPIBASE_LIBS} -lgssapi -lkrb5 -lasn1 -lroken ${LIB_CRYPT} -lcom_err ${LIB_SOCKET})
    if test "$gss_impl" != "auto" -a "$gss_failed" = "1"; then
      gss_impl="failed"
    fi
  fi

  if test "$gss_impl" = "auto" -o "$gss_impl" = "mit"; then
    gss_failed=0
    AC_CHECK_LIB(gssapi_krb5,gss_unwrap,gss_impl="mit",gss_failed=1,
                 ${GSSAPIBASE_LIBS} -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err ${LIB_SOCKET})
    if test "$gss_impl" != "auto" -a "$gss_failed" = "1"; then
      gss_impl="failed"
    fi
  fi

  # For Cybersafe one has to set a platform define in order to make compilation work
  if test "$gss_impl" = "auto" -o "$gss_impl" = "cybersafe"; then

    cmu_saved_CPPFLAGS=$CPPFLAGS
    cmu_saved_GSSAPIBASE_LIBS=$GSSAPIBASE_LIBS
# FIXME - Note that the libraries are in .../lib64 for 64bit kernels
    if test -d "${gssapi}/appsec-rt/lib"; then
      GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -L${gssapi}/appsec-rt/lib"
    fi
    CPPFLAGS="$CPPFLAGS -D$platform"
    if test -d "${gssapi}/appsec-sdk/include"; then
      CPPFLAGS="$CPPFLAGS -I${gssapi}/appsec-sdk/include"
    fi

    gss_failed=0

# Check for CyberSafe with two libraries first, than fall back to a single 
# library (older CyberSafe)

    unset ac_cv_lib_gss_csf_gss_acq_user
    AC_CHECK_LIB(gss,csf_gss_acq_user,gss_impl="cybersafe03",
                 [unset ac_cv_lib_gss_csf_gss_acq_user;
                  AC_CHECK_LIB(gss,csf_gss_acq_user,gss_impl="cybersafe",
                               gss_failed=1,$GSSAPIBASE_LIBS -lgss)],
                 [${GSSAPIBASE_LIBS} -lgss -lcstbk5])

    if test "$gss_failed" = "1"; then
# Restore variables
      GSSAPIBASE_LIBS=$cmu_saved_GSSAPIBASE_LIBS
      CPPFLAGS=$cmu_saved_CPPFLAGS

      if test "$gss_impl" != "auto"; then
        gss_impl="failed"
      fi
    fi
  fi

  if test "$gss_impl" = "auto" -o "$gss_impl" = "seam"; then
    gss_failed=0
    AC_CHECK_LIB(gss,gss_unwrap,gss_impl="seam",gss_failed=1,-lgss)
    if test "$gss_impl" != "auto" -a "$gss_failed" = "1"; then
      gss_impl="failed"
    fi
  fi

  if test "$gss_impl" = "mit"; then
    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi_krb5 -lkrb5 -lk5crypto -lcom_err"
    GSSAPIBASE_STATIC_LIBS="$GSSAPIBASE_LIBS $gssapi_dir/libgssapi_krb5.a $gssapi_dir/libkrb5.a $gssapi_dir/libk5crypto.a $gssapi_dir/libcom_err.a"
  elif test "$gss_impl" = "heimdal"; then
    CPPFLAGS="$CPPFLAGS"
    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgssapi -lkrb5 -lasn1 -lroken ${LIB_CRYPT} -lcom_err"
    GSSAPIBASE_STATIC_LIBS="$GSSAPIBASE_STATIC_LIBS $gssapi_dir/libgssapi.a $gssapi_dir/libkrb5.a $gssapi_dir/libasn1.a $gssapi_dir/libroken.a $gssapi_dir/libcom_err.a ${LIB_CRYPT}"
  elif test "$gss_impl" = "cybersafe03"; then
# Version of CyberSafe with two libraries
    CPPFLAGS="$CPPFLAGS -D$platform -I${gssapi}/appsec-sdk/include"
    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgss -lcstbk5"
    # there is no static libgss for CyberSafe
    GSSAPIBASE_STATIC_LIBS=none
  elif test "$gss_impl" = "cybersafe"; then
    CPPFLAGS="$CPPFLAGS -D$platform -I${gssapi}/appsec-sdk/include"
    GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lgss"
    # there is no static libgss for CyberSafe
    GSSAPIBASE_STATIC_LIBS=none
  elif test "$gss_impl" = "seam"; then
    GSSAPIBASE_LIBS=-lgss
    # there is no static libgss on Solaris 8 and up
    GSSAPIBASE_STATIC_LIBS=none
  elif test "$gss_impl" = "failed"; then
    gssapi="no"
    GSSAPIBASE_LIBS=
    GSSAPIBASE_STATIC_LIBS=
    AC_WARN([Disabling GSSAPI - specified library not found])
  else
    gssapi="no"
    GSSAPIBASE_LIBS=
    GSSAPIBASE_STATIC_LIBS=
    AC_WARN([Disabling GSSAPI - no library])
  fi
fi

#
# Cybersafe defines both GSS_C_NT_HOSTBASED_SERVICE and GSS_C_NT_USER_NAME
# in gssapi\rfckrb5.h
#
if test "$gssapi" != "no"; then
  if test "$gss_impl" = "cybersafe" -o "$gss_impl" = "cybersafe03"; then
    AC_EGREP_CPP(hostbased_service_gss_nt_yes,
                 [#include <gssapi/gssapi.h>
                  #ifdef GSS_C_NT_HOSTBASED_SERVICE
                    hostbased_service_gss_nt_yes
                  #endif],
                 [AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE,,
                            [Define if your GSSAPI implementation defines GSS_C_NT_HOSTBASED_SERVICE])],
                 [AC_WARN([Cybersafe define not found])])

  elif test "$ac_cv_header_gssapi_h" = "yes"; then
    AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi.h,
                    [AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE,,
                               [Define if your GSSAPI implementation defines GSS_C_NT_HOSTBASED_SERVICE])])
  elif test "$ac_cv_header_gssapi_gssapi_h"; then
    AC_EGREP_HEADER(GSS_C_NT_HOSTBASED_SERVICE, gssapi/gssapi.h,
                    [AC_DEFINE(HAVE_GSS_C_NT_HOSTBASED_SERVICE,,
                               [Define if your GSSAPI implementation defines GSS_C_NT_HOSTBASED_SERVICE])])
  fi

  if test "$gss_impl" = "cybersafe" -o "$gss_impl" = "cybersafe03"; then
    AC_EGREP_CPP(user_name_yes_gss_nt,
                 [#include <gssapi/gssapi.h>
                  #ifdef GSS_C_NT_USER_NAME
                   user_name_yes_gss_nt
                  #endif],
                 [AC_DEFINE(HAVE_GSS_C_NT_USER_NAME,,
                            [Define if your GSSAPI implementation defines GSS_C_NT_USER_NAME])],
                 [AC_WARN([Cybersafe define not found])])
  elif test "$ac_cv_header_gssapi_h" = "yes"; then
    AC_EGREP_HEADER(GSS_C_NT_USER_NAME, gssapi.h,
                    [AC_DEFINE(HAVE_GSS_C_NT_USER_NAME,,
                               [Define if your GSSAPI implementation defines GSS_C_NT_USER_NAME])])
    AC_EGREP_HEADER(gss_inquire_attrs_for_mech, gssapi.h, rfc5587=yes)
    AC_EGREP_HEADER(gss_inquire_mech_for_saslname, gssapi.h, rfc5801=yes)
  elif test "$ac_cv_header_gssapi_gssapi_h"; then
    AC_EGREP_HEADER(GSS_C_NT_USER_NAME, gssapi/gssapi.h,
                    [AC_DEFINE(HAVE_GSS_C_NT_USER_NAME,,
                               [Define if your GSSAPI implementation defines GSS_C_NT_USER_NAME])])
    AC_EGREP_HEADER(gss_inquire_attrs_for_mech, gssapi/gssapi.h, rfc5587=yes)
    AC_EGREP_HEADER(gss_inquire_mech_for_saslname, gssapi.h, rfc5801=yes)
  fi
fi

AC_MSG_CHECKING([GSSAPI])
if test "$gssapi" != no; then
  AC_MSG_RESULT([with implementation ${gss_impl}])
  AC_CHECK_LIB(resolv,res_search,GSSAPIBASE_LIBS="$GSSAPIBASE_LIBS -lresolv")
  SASL_MECHS="$SASL_MECHS libgssapiv2.la"
  SASL_STATIC_OBJS="$SASL_STATIC_OBJS gssapi.o"
  SASL_STATIC_SRCS="$SASL_STATIC_SRCS \$(top_srcdir)/plugins/gssapi.c"
  if test "$rfc5587" = "yes" -a "$rfc5801" = "yes"; then
    gs2="yes"
    SASL_MECHS="$SASL_MECHS libgs2.la"
    SASL_STATIC_OBJS="$SASL_STATIC_OBJS gs2.o"
    SASL_STATIC_SRCS="$SASL_STATIC_SRCS \$(top_srcdir)/plugins/gs2.c"
  fi

  cmu_save_LIBS="$LIBS"
  LIBS="$LIBS $GSSAPIBASE_LIBS"
  AC_CHECK_HEADERS(gssapi/gssapi_krb5.h)
  AC_CHECK_FUNCS(gsskrb5_register_acceptor_identity)
  if test "$ac_cv_func_gsskrb5_register_acceptor_identity" = no ; then
    if test "$ac_cv_header_gssapi_gssapi_krb5_h" = "yes"; then
      AC_CHECK_DECL(gsskrb5_register_acceptor_identity,
                    [AC_DEFINE(HAVE_GSSKRB5_REGISTER_ACCEPTOR_IDENTITY,1,
                               [Define if your GSSAPI implementation defines gsskrb5_register_acceptor_identity])],,
                    [
                    AC_INCLUDES_DEFAULT
                    #include <gssapi/gssapi_krb5.h>
                    ])
    fi
  fi
  AC_CHECK_FUNCS(gss_decapsulate_token)
  AC_CHECK_FUNCS(gss_encapsulate_token)
  AC_CHECK_FUNCS(gss_oid_equal)
  LIBS="$cmu_save_LIBS"

  cmu_save_LIBS="$LIBS"
  LIBS="$LIBS $GSSAPIBASE_LIBS"
  if test "$ac_cv_header_gssapi_gssapi_krb5_h" = "yes"; then
    AC_CHECK_DECL(GSS_KRB5_CRED_NO_CI_FLAGS_X,
                  [AC_DEFINE(HAVE_GSS_KRB5_CRED_NO_CI_FLAGS_X,1,
                             [Define if your GSSAPI implementation supports GSS_KRB5_CRED_NO_CI_FLAGS_X])],,
                  [
                    AC_INCLUDES_DEFAULT
                    #include <gssapi/gssapi_krb5.h>
                    ])
  fi
  LIBS="$cmu_save_LIBS"

  cmu_save_LIBS="$LIBS"
  LIBS="$LIBS $GSSAPIBASE_LIBS"
  AC_CHECK_FUNCS(gss_get_name_attribute)
  LIBS="$cmu_save_LIBS"

  cmu_save_LIBS="$LIBS"
  LIBS="$LIBS $GSSAPIBASE_LIBS"
  AC_CHECK_FUNCS(gss_inquire_sec_context_by_oid)
  if test "$ac_cv_func_gss_inquire_sec_context_by_oid" = no ; then
    if test "$ac_cv_header_gssapi_gssapi_ext_h" = "yes"; then
      AC_CHECK_DECL(gss_inquire_sec_context_by_oid,
                    [AC_DEFINE(HAVE_GSS_INQUIRE_SEC_CONTEXT_BY_OID,1,
                               [Define if your GSSAPI implementation defines gss_inquire_sec_context_by_oid])],,
                    [
                    AC_INCLUDES_DEFAULT
                    #include <gssapi/gssapi_ext.h>
                    ])
    fi
  fi
  if test "$ac_cv_header_gssapi_gssapi_ext_h" = "yes"; then
    AC_EGREP_HEADER(GSS_C_SEC_CONTEXT_SASL_SSF, gssapi/gssapi_ext.h,
                    [AC_DEFINE(HAVE_GSS_C_SEC_CONTEXT_SASL_SSF,,
                               [Define if your GSSAPI implementation defines GSS_C_SEC_CONTEXT_SASL_SSF])])
  fi
  LIBS="$cmu_save_LIBS"

  AC_CACHE_CHECK([for SPNEGO support in GSSAPI libraries],[ac_cv_gssapi_supports_spnego],[
    cmu_save_LIBS="$LIBS"
    LIBS="$LIBS $GSSAPIBASE_LIBS"
    AC_TRY_RUN([
#ifdef HAVE_GSSAPI_H
#include <gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif

int main(void)
{
    gss_OID_desc spnego_oid = { 6, (void *) "\x2b\x06\x01\x05\x05\x02" };
    gss_OID_set mech_set;
    OM_uint32 min_stat;
    int have_spnego = 0;
                                                                               
    if (gss_indicate_mechs(&min_stat, &mech_set) == GSS_S_COMPLETE) {
	gss_test_oid_set_member(&min_stat, &spnego_oid, mech_set, &have_spnego);
	gss_release_oid_set(&min_stat, &mech_set);
    }

    return (!have_spnego);  // 0 = success, 1 = failure
}
],[ac_cv_gssapi_supports_spnego=yes],[ac_cv_gssapi_supports_spnego=no])
    LIBS="$cmu_save_LIBS"
  ])
  AS_IF([test "$ac_cv_gssapi_supports_spnego" = yes],[
    AC_DEFINE(HAVE_GSS_SPNEGO,,[Define if your GSSAPI implementation supports SPNEGO])
  ])

else
  AC_MSG_RESULT([disabled])
fi
AC_SUBST(GSSAPIBASE_LIBS)
])# SASL_GSSAPI_CHK


# SASL2_CRYPT_CHK
# ---------------
AC_DEFUN([SASL2_CRYPT_CHK],
[AC_CHECK_FUNC(crypt, cmu_have_crypt=yes,
               [AC_CHECK_LIB(crypt, crypt,
                             LIB_CRYPT="-lcrypt"; cmu_have_crypt=yes,
                             cmu_have_crypt=no)])
AC_SUBST(LIB_CRYPT)
])# SASL2_CRYPT_CHK

dnl Check for NT Threads
AC_DEFUN([SASL2_NT_THREADS], [
	AC_CHECK_FUNC(_beginthread)

	if test $ac_cv_func__beginthread = yes ; then
		AC_DEFINE(HAVE_NT_THREADS,1,[if you have NT Threads])
		sasl2_cv_nt_threads=yes
	fi
])
