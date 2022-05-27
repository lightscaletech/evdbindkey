AC_INIT([evdbindkey], [0.1.0])

AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])

: ${CFLAGS="-O2"}

AC_PROG_CC
AC_C_CONST
AC_C_VARARRAYS
AC_FUNC_MALLOC
AC_PROG_SED

AC_CHECK_INCLUDES_DEFAULT

AC_CHECK_HEADER([fcntl.h], [], [
   echo "Missing fcntl.h header"
   exit -1
])

AC_CHECK_HEADER([errno.h], [], [
    echo "Missing errno.h header"
    exit -1
])

AC_CHECK_HEADER([signal.h], [], [
    echo "Missing signal.h header"
    exit -1
])

AC_CHECK_HEADER([poll.h], [], [
    echo "Missing poll.h header"
    exit -1
])

AC_CHECK_HEADER([regex.h], [], [
    echo "Missing regex.h header"
    exit -1
])

AC_CHECK_HEADER([sys/socket.h], [], [
    echo "Missing sys/socket.h header"
    exit -1
])

AC_CHECK_HEADER([sys/un.h], [], [
    echo "Missing sys/un.h header"
    exit -1
])

AC_CHECK_HEADER([sys/wait.h], [], [
    echo "Missing sys/wait.h header"
    exit -1
])

PKG_CHECK_MODULES([LIBEVDEV], [libevdev])
PKG_CHECK_MODULES([LIBUDEV], [libudev])

AC_DEFINE([IPC_SOCK_PATH], ["/var/run/evdkeybind.sock"], [Path to the IPC socket])
AC_DEFINE([KEYSTROKE_MAX_SIZE], [6], [Maximum size of keystroke])

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug], [enable debugging, default: yes]),
    [case "${enableval}" in
          yes) debug=true ;;
          no)  debug=false ;;
          *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
     esac],
     [debug=true])

if test x"$debug" = x"true"; then
   CFLAGS="$CFLAGS -g"
fi

CFLAGS="$CFLAGS -Wall"

# Systemd unit directory
AC_ARG_WITH([systemdsystemunitdir],
    [AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files])],,
    [with_systemdsystemunitdir=auto])

AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
      def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
      AS_IF([test "x$def_systemdsystemunitdir" = "x"],
            [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
                   [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
             with_systemdsystemunitdir=no],
      [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])

AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
      [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])

AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])

AC_CONFIG_FILES([
    Makefile
])
AC_OUTPUT
