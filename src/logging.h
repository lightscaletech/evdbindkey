#include <stdio.h>
#include <string.h>


#include <string>
#include <iostream>

enum log_level {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO
};

#define _LOG_FN_DEF(type) void _log_##type(std::string, int line, const char *, ...)

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

#ifndef DEBUG_GL_DISABLED
#define log_gl_errors() _log_gl_errors(__FILENAME__, __LINE__)
#else
#define log_gl_errors()
#endif

template<class T>
void _log_vector(std::string fn, int ln, std::string fmt, T v) {
    const std::string text = "DEBUG";
    std::string res = "Logging vector: \n (\n";
    unsigned short i = 0, len = v.size();
    char tmp[20];

    std::string fmt2 = "%d = ";
    fmt2 += fmt;

    for(i = 0; i < len; i++) {
        sprintf(tmp, fmt2.c_str(), i, v[i]);
        res += "   " + std::string(tmp) + ", \n";
    }

    res += ")";

    std::cout << text << ": " << fn << ":" << ln << ": " << res << std::endl;

}

#define log_vector(type, fmt, v) _log_vector<type>(__FILENAME__, __LINE__, fmt, v)


void _log_gl_errors(const char *, int);
