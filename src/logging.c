#include "logging.h"

#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"

static void _log(const char * file, int ln, unsigned int lv, const char *fm, va_list args) {
    char * text;
    char * color;

    switch(lv) {
    case LOG_LEVEL_DEBUG:
        text = "DEBUG";
        color = COLOR_BLUE;
        break;
    case LOG_LEVEL_ERROR:
        text = "ERROR";
        color = COLOR_RED;
        break;
    case LOG_LEVEL_WARN:
        text = "WARN";
        color = COLOR_YELLOW;
        break;
    case LOG_LEVEL_INFO:
        text = "INFO";
        color = COLOR_GREEN;
        break;
    }

    fprintf(stderr, "%s%s%s: %s:%d: ", color, text, COLOR_RESET, file, ln);
    vfprintf(stderr, fm, args);
    fprintf(stderr, "\n");
}

#define LOG_FN(type, lv)                        \
    void _log_##type(const char * file, int ln, const char *fm, ...) {  \
        va_list args;                           \
        va_start(args, fm);                     \
        _log(file, ln, lv, fm, args);           \
        va_end(args);                           \
    }

LOG_FN(debug, LOG_LEVEL_DEBUG);
LOG_FN(error, LOG_LEVEL_ERROR);
LOG_FN(warn,  LOG_LEVEL_WARN);
LOG_FN(info,  LOG_LEVEL_INFO);
