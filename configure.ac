AC_INIT(pam_groupmember, 0.1)
AC_CONFIG_HEADERS(config.h)
AC_PROG_INSTALL
AM_INIT_AUTOMAKE
AC_PROG_CC
AM_PROG_CC_C_O
AC_DISABLE_STATIC
AM_PROG_LIBTOOL

AC_ARG_WITH([slibdir], AS_HELP_STRING([--with-slibdir=PATH],
			[Path to the super lib directory [[/lib]]]),
		[slibdir="$withval"], [slibdir="/lib"])
AC_SUBST(slibdir)

AC_CHECK_HEADER(grp.h)
AC_CHECK_HEADER(pwd.h)
AC_CHECK_HEADER(sys/syslog.h)
AC_CHECK_HEADER(security/pam_modules.h, [have_pamheader="yes"])
if test x"$have_pamheader" != x"yes"; then
	AC_CHECK_HEADER(pam/pam_modules.h, [have_pamheader="yes"])
fi
if test x"$have_pamheader" != x"yes"; then
	AC_MSG_ERROR([You are missing PAM headers])
fi

case "$host" in
    (*-*-linux*)
	PAM_MODDIR='${slibdir}/security'
	;;
    (*)
	PAM_MODDIR="/usr/lib"
	;;
esac
AC_SUBST(PAM_MODDIR)

AC_ARG_ENABLE([debug],
		[AS_HELP_STRING([--enable-debug],
			[enables debugging output (default is no)])],
		[debug=1],
		[debug=0])
if test x"$debug" = "x1"; then
	AC_DEFINE([DEBUG], [1], [enable debugging output])
fi

AC_OUTPUT([Makefile])
