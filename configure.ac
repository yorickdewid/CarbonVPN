AC_PREREQ([2.69])
AC_INIT(CarbonVPN, CarbonVPN 0.6, https://github.com/yorickdewid/CarbonVPN)
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([logger.c])
AC_CONFIG_HEADERS([config.h])
AC_MSG_NOTICE([CarbonVPN])

# Checks for programs
AC_PROG_CC_STDC

CFLAGS="$CFLAGS -pedantic -Wall -Wextra -Werror";
LDFLAGS="$LDFLAGS -lev -lsodium ";

CFLAGS="$CFLAGS -fno-strict-aliasing";
CFLAGS="$CFLAGS -Wno-unused-parameter";
CFLAGS="$CFLAGS -Wno-old-style-declaration";

# Checks for libraries.
AC_CHECK_LIB(ev, ev_io_init)
AC_CHECK_LIB(sodium, sodium_init)

# Checks for header files
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h endian.h])
AC_CHECK_HEADERS([linux/if.h linux/if_tun.h])
AC_CHECK_HEADERS([getopt.h stdarg.h errno.h])
AC_CHECK_HEADERS([sodium.h ev.h])

# Checks for typedefs, structures, and compiler characteristics
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_C_INLINE
AC_C_BIGENDIAN(
  AC_DEFINE(NATIVE_BIG_ENDIAN, 1, [machine is bigendian]),
  AC_DEFINE(NATIVE_LITTLE_ENDIAN, 1, [machine is littleendian]),
  AC_MSG_ERROR([unknown endianess]),
  AC_MSG_ERROR([universal endianess is not supported - compile separately and use lipo(1)])
)

# Checks for library functions
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([inet_ntoa memset socket strdup strtol])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
