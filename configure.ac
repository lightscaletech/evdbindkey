AC_INIT([keybindings],[0.0.1])

AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR
AC_C_CONST
AC_C_VARARRAYS
AC_FUNC_MALLOC

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

AC_CHECK_HEADER([sys/socket.h], [], [
    echo "Missing sys/socket.h header"
    exit -1
])

AC_CHECK_HEADER([sys/un.h], [], [
    echo "Missing sys/un.h header"
    exit -1
])

PKG_CHECK_MODULES([LIBEVDEV], [libevdev])
PKG_CHECK_MODULES([LIBUDEV], [libudev])

AC_DEFINE([IPC_SOCK_PATH], ["/tmp/keybindings.sock"], [Path to the IPC socket])
AC_DEFINE([KEYSTROKE_MAX_SIZE], [6], [Maximum size of keystroke])

CFLAGS="$CFLAGS -Wall"

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
