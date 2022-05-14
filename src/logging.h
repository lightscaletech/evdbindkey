#ifndef _KEYBINDINGS_LOGGING_H_
#define _KEYBINDINGS_LOGGING_H_

#include "../config.h"

#include <stdio.h>
#include <string.h>

#define LOG_LEVEL_DEBUG 1
#define LOG_LEVEL_INFO  2
#define LOG_LEVEL_WARN  3
#define LOG_LEVEL_ERROR 4

#define _LOG_FN_DEF(type) void _log_##type(const char *, int line, const char *, ...)

_LOG_FN_DEF(error);
_LOG_FN_DEF(debug);
_LOG_FN_DEF(warn);
_LOG_FN_DEF(info);

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define log_debug(text, ...)                            \
    _log_debug( __FILENAME__, __LINE__, text __VA_OPT__(,) __VA_ARGS__)

#define log_warn(text, ...)                             \
    _log_warn(  __FILENAME__, __LINE__, text __VA_OPT__(,) __VA_ARGS__)

#define log_info(text, ...)                             \
    _log_info(  __FILENAME__, __LINE__, text __VA_OPT__(,) __VA_ARGS__)

#define log_error(text, ...)                            \
    _log_error( __FILENAME__, __LINE__, text __VA_OPT__(,) __VA_ARGS__)

#endif
