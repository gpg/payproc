# configure.ac - for Payproc
# Copyright (C) 2014, 2015 g10 Code GmbH
#
# This file is part of Payproc.
#
# Payproc is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Payproc is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.69)
min_automake_version="1.14"

# To build a release you need to create a tag with the version number
# (git tag -s payproc-0.n.m) and run "./autogen.sh --force".  Please
# bump the version number immediately *after* the release and do
# another commit and push so that the git magic is able to work.
m4_define([mym4_version], [0.3.0])

# Below is m4 magic to extract and compute the git revision number,
# the decimalized short revision number, a beta version string and a
# flag indicating a development version (mym4_isgit).  Note that the
# m4 processing is done by autoconf and not during the configure run.
m4_define([mym4_revision],
          m4_esyscmd([git rev-parse --short HEAD | tr -d '\n\r']))
m4_define([mym4_revision_dec],
          m4_esyscmd_s([echo $((0x$(echo ]mym4_revision[|head -c 4)))]))
m4_define([mym4_betastring],
          m4_esyscmd_s([git describe --match 'payproc-0.[0-9].*[0-9]' --long|\
                        awk -F- '$3!=0{print"-beta"$3}']))
m4_define([mym4_isgit],m4_if(mym4_betastring,[],[no],[yes]))
m4_define([mym4_full_version],[mym4_version[]mym4_betastring])

AC_INIT([payproc],[mym4_full_version], [http://bugs.gnupg.org])

NEED_GPG_ERROR_VERSION=1.18

NEED_LIBASSUAN_API=2
NEED_LIBASSUAN_VERSION=2.1.0

NEED_NPTH_API=1
NEED_NPTH_VERSION=0.91

NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.6.0

NEED_GNUTLS_VERSION=3.0

development_version=mym4_isgit

AC_CONFIG_AUX_DIR(build-aux)
AC_CONFIG_SRCDIR(src/payprocd.c)
AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE([serial-tests dist-bzip2 no-dist-gzip])
AC_CANONICAL_HOST

AC_GNU_SOURCE

AC_DEFINE_UNQUOTED(PACKAGE_BUGREPORT, "$PACKAGE_BUGREPORT",
                                        [Bug report address])
AC_DEFINE_UNQUOTED(NEED_LIBGCRYPT_VERSION, "$NEED_LIBGCRYPT_VERSION",
                                       [Required version of Libgcrypt])

AC_ARG_VAR([PAYPROCD_SOCKET_NAME], [Name of the socket to connect payprocd])dnl
test -z "$PAYPROCD_SOCKET_NAME" && PAYPROCD_SOCKET_NAME=/var/run/payproc/daemon
AC_DEFINE_UNQUOTED([PAYPROCD_SOCKET_NAME], "$PAYPROCD_SOCKET_NAME",
                                    [Name of the socket to connect payprocd])

AC_ARG_VAR([PAYPROCD_TEST_SOCKET_NAME],
           [Name of the socket to connect the payprocd test instanace])dnl
test -z "$PAYPROCD_TEST_SOCKET_NAME" \
    && PAYPROCD_TEST_SOCKET_NAME=/var/run/payproc-test/daemon
AC_DEFINE_UNQUOTED([PAYPROCD_TEST_SOCKET_NAME], "$PAYPROCD_TEST_SOCKET_NAME",
                   [Name of the socket to connect a payprocd test intance])


#
# To avoid double inclusion of config.h which might happen at some
# places, we add the usual double inclusion protection at the top of
# config.h.
#
AH_TOP([
#ifndef PAYPROC_CONFIG_H_INCLUDED
#define PAYPROC_CONFIG_H_INCLUDED
])

#
# Stuff which goes at the bottom of config.h.
#
AH_BOTTOM([

/* Provide the es_ macro for estream.  */
#define GPGRT_ENABLE_ES_MACROS 1

/* Tell Libgcrypt not to include deprecated definitions.  */
#define GCRYPT_NO_DEPRECATED 1


#endif /*GNUPG_CONFIG_H_INCLUDED*/
])


AM_MAINTAINER_MODE

# Checks for programs.
AC_MSG_NOTICE([checking for programs])
AC_PROG_MAKE_SET
AM_SANITY_CHECK
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
if test "x$ac_cv_prog_cc_c89" = "xno" ; then
  AC_MSG_ERROR([[No C-89 compiler found]])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB
AC_CHECK_TOOL(AR, ar, :)
AC_ISC_POSIX
AC_SYS_LARGEFILE

#
# Checks for libraries.
#
AC_MSG_NOTICE([checking for libraries])


#
# libgpg-error is a library with error codes shared between GnuPG
# related projects.
#
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes,have_gpg_error=no)


#
# Check whether the nPth library is available
#
AM_PATH_NPTH("$NEED_NPTH_API:$NEED_NPTH_VERSION",have_npth=yes,have_npth=no)
if test "$have_npth" = "yes"; then
  AC_DEFINE(HAVE_NPTH, 1,
              [Defined if the New Portable Thread Library is available])
  AC_DEFINE(USE_NPTH, 1,
              [Defined if support for nPth is requested and nPth is available])
else
  AC_MSG_WARN([[
***
*** To support concurrent access
*** we need the New Portable Threads Library.
***]])
fi


#
# We need Libgcrypt for its RNG and the hash fucntion.  Maybe for more
# things in the future.
#
AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_API:$NEED_LIBGCRYPT_VERSION",
        have_libgcrypt=yes,have_libgcrypt=no)


#
# GNUTLS
#
PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= $NEED_GNUTLS_VERSION],
                               [have_gnutls=yes],
                               [have_gnutls=no])
if test "$have_gnutls" = "yes"; then
  AC_SUBST([LIBGNUTLS_CFLAGS])
  AC_SUBST([LIBGNUTLS_LIBS])
  AC_DEFINE(HTTP_USE_GNUTLS, 1, [Enable GNUTLS support in http.c])
else
  tmp=$(echo "$LIBGNUTLS_PKG_ERRORS" | tr '\n' '\v' | sed 's/\v/\n*** /g')
  AC_MSG_WARN([[
***
*** GNUTLS not found
***
*** $tmp]])
fi

#
# SQLite
#
PKG_CHECK_MODULES([SQLITE3],[sqlite3 >= 3.8],
                            [have_sqlite3=yes],
                            [have_sqlite3=no])
if test "$have_sqlite3" = "yes"; then
  AC_SUBST([SQLITE3_CFLAGS])
  AC_SUBST([SQLITE3_LIBS])
  :
else
  tmp=$(echo "$SQLITE3_PKG_ERRORS" | tr '\n' '\v' | sed 's/\v/\n*** /g')
  AC_MSG_WARN([[
***
*** SQLite3 not found
***
*** $tmp]])
fi


AC_MSG_NOTICE([checking for networking options])

#
# Must check for network library requirements before doing link tests
# for ldap, for example. If ldap libs are static (or dynamic and without
# ELF runtime link paths), then link will fail and LDAP support won't
# be detected.
#
AC_CHECK_FUNC(gethostbyname, , AC_CHECK_LIB(nsl, gethostbyname,
	[NETLIBS="-lnsl $NETLIBS"]))
AC_CHECK_FUNC(setsockopt, , AC_CHECK_LIB(socket, setsockopt,
	[NETLIBS="-lsocket $NETLIBS"]))


#
# Checking for iconv
#
AM_ICONV


#
# Checks for header files.
#
AC_MSG_NOTICE([checking for header files])
AC_HEADER_STDC
AC_CHECK_HEADERS([unistd.h inttypes.h signal.h])
AC_HEADER_TIME


#
# Checks for typedefs, structures, and compiler characteristics.
#
AC_MSG_NOTICE([checking for system characteristics])
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_TYPE_SIGNAL
AC_DECL_SYS_SIGLIST


#
# Checks for library functions.
#
AC_MSG_NOTICE([checking for library functions])
AC_CHECK_FUNCS([strerror strlwr gmtime_r])

# For http.c
AC_CHECK_FUNCS([strtoull])

# Check for the getsockopt SO_PEERCRED
AC_MSG_CHECKING(for SO_PEERCRED)
AC_CACHE_VAL(payproc_cv_sys_so_peercred,
      [AC_TRY_COMPILE([#include <sys/socket.h>],
         [struct ucred cr;
          int cl = sizeof cr;
          getsockopt (1, SOL_SOCKET, SO_PEERCRED, &cr, &cl);],
          payproc_cv_sys_so_peercred=yes,
          payproc_cv_sys_so_peercred=no)
       ])
AC_MSG_RESULT($payproc_cv_sys_so_peercred)

if test $payproc_cv_sys_so_peercred = yes; then
  AC_DEFINE(HAVE_SO_PEERCRED, 1,
            [Defined if SO_PEERCRED is supported (Linux specific)])
else
  # Check for the getsockopt LOCAL_PEEREID (NetBSD)
  AC_MSG_CHECKING(for LOCAL_PEEREID)
  AC_CACHE_VAL(payproc_cv_sys_so_local_peereid,
      [AC_TRY_COMPILE([#include <sys/socket.>
         #include <sys/un.h>],
         [struct unpcbid unp;
          int unpl = sizeof unp;
          getsockopt (1, SOL_SOCKET, LOCAL_PEEREID, &unp, &unpl);],
          payproc_cv_sys_so_local_peereid=yes,
          payproc_cv_sys_so_local_peereid=no)
       ])
  AC_MSG_RESULT($payproc_cv_sys_so_local_peereid)

  if test $payproc_cv_sys_so_local_peereid = yes; then
    AC_DEFINE(HAVE_LOCAL_PEEREID, 1,
              [Defined if LOCAL_PEEREID is supported (NetBSD specific)])
  else
    # (Open)Solaris
    AC_CHECK_FUNCS([getpeerucred], AC_CHECK_HEADERS([ucred.h]))
    if test $ac_cv_func_getpeerucred != yes; then
        # FreeBSD
        AC_CHECK_FUNCS([getpeereid])
    fi
  fi
fi


#
# Setup gcc specific options
#
AC_MSG_NOTICE([checking for cc features])
if test "$GCC" = yes; then
    # Check whether gcc does not emit a diagnostic for unknown -Wno-*
    # options.  This is the case for gcc >= 4.6.
    AC_MSG_CHECKING([if gcc ignores unknown -Wno-* options])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 6 )
#kickerror
#endif]],[])],
      [_gcc_silent_wno=yes],[_gcc_silent_wno=no])
    AC_MSG_RESULT($_gcc_silent_wno)

    # Note that it is okay to use CFLAGS here because these are just
    # warning options and the user should have a chance of overriding
    # them.
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -O3 -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        CFLAGS="$CFLAGS -Wformat -Wno-format-y2k -Wformat-security"
        if test x"$_gcc_silent_wno" = xyes ; then
          _gcc_wopt=yes
        else
          AC_MSG_CHECKING([if gcc supports -Wno-missing-field-initializers])
          _gcc_cflags_save=$CFLAGS
          CFLAGS="-Wno-missing-field-initializers"
          AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                            [_gcc_wopt=yes],[_gcc_wopt=no])
          AC_MSG_RESULT($_gcc_wopt)
          CFLAGS=$_gcc_cflags_save;
        fi
        if test x"$_gcc_wopt" = xyes ; then
          CFLAGS="$CFLAGS -W -Wno-sign-compare -Wno-missing-field-initializers"
        fi

        AC_MSG_CHECKING([if gcc supports -Wdeclaration-after-statement])
        _gcc_cflags_save=$CFLAGS
        CFLAGS="-Wdeclaration-after-statement"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_wopt=yes,_gcc_wopt=no)
        AC_MSG_RESULT($_gcc_wopt)
        CFLAGS=$_gcc_cflags_save;
        if test x"$_gcc_wopt" = xyes ; then
          CFLAGS="$CFLAGS -Wdeclaration-after-statement"
        fi
    else
        CFLAGS="$CFLAGS -Wall"
    fi

    if test x"$_gcc_silent_wno" = xyes ; then
      _gcc_psign=yes
    else
      AC_MSG_CHECKING([if gcc supports -Wno-pointer-sign])
      _gcc_cflags_save=$CFLAGS
      CFLAGS="-Wno-pointer-sign"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
                        [_gcc_psign=yes],[_gcc_psign=no])
      AC_MSG_RESULT($_gcc_psign)
      CFLAGS=$_gcc_cflags_save;
    fi
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wno-pointer-sign"
    fi

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wpointer-arith"
    fi
fi


#
# This is handy for debugging so the compiler doesn't rearrange
# things and eliminate variables.
#
AC_ARG_ENABLE(optimization,
   AC_HELP_STRING([--disable-optimization],
                  [disable compiler optimization]),
                  [if test $enableval = no ; then
                      CFLAGS=`echo $CFLAGS | sed s/-O[[1-9]]\ /-O0\ /g`
                   fi])

#
# Print errors here so that they are visible all
# together and the user can acquire them all together.
#
die=no
if test "$have_gpg_error" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libgpg-error to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgpg-error
*** (at least version $NEED_GPG_ERROR_VERSION is required.)
***]])
fi
if test "$have_npth" = "no"; then
    die=yes
    AC_MSG_NOTICE([[
***
*** It is required to build with support for the
*** New Portable Threads Library (nPth). Please install this
*** library first.  The library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/npth/
*** (at least version $NEED_NPTH_VERSION (API $NEED_NPTH_API) is required).
***]])
fi
if test "$have_libgcrypt" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need libgcrypt to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgcrypt/
*** (at least version $NEED_LIBGCRYPT_VERSION (API $NEED_LIBGCRYPT_API) is required.)
***]])
fi
if test "$have_gnutls" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need GNUTLS to build this program.
**  This library is for example available at
***   ftp://ftp.gnutls.org/gcrypt/gnutls/
*** (at least version $NEED_GNUTLS_VERSION is required.)
***]])
fi
if test "$have_sqlite3" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***
*** You need SQLite3 to build this program.
***]])
fi

if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi



AC_CONFIG_FILES([Makefile
m4/Makefile
src/Makefile
doc/Makefile
tests/Makefile
])


AC_OUTPUT


echo "
        Payproc v${PACKAGE_VERSION} has been configured as follows:

        Revision:  mym4_revision
        Platform:  $host

"
