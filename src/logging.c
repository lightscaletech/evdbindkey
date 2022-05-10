#include "logging.h"

#include <stdarg.h>
#include <string.h>
#include <string>
#include <iostream>

#include <glad/glad.h>

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"

static void _log(std::string file, int ln, enum log_level lv, const char *fm, va_list args) {
    std::string text;
    std::string color;

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

    std::cout << color << text << COLOR_RESET << ": "
              << file << ":" << ln << ": ";
    //printf("%s%s%s: %s:%d: ", color, text, COLOR_RESET, file, ln);
    vprintf(fm, args);
    printf("\n");
}

#define LOG_FN(type, lv)                        \
    void _log_##type(std::string file, int ln, const char *fm, ...) {  \
        va_list args;                           \
        va_start(args, fm);                     \
        _log(file, ln, lv, fm, args);           \
        va_end(args);                           \
    }

LOG_FN(debug, LOG_LEVEL_DEBUG);
LOG_FN(error, LOG_LEVEL_ERROR);
LOG_FN(warn,  LOG_LEVEL_WARN);
LOG_FN(info,  LOG_LEVEL_INFO);

static void gl_err_str(GLenum err) {
#define CASE(e) case e:  printf("\t%s\n", #e); break;
    switch(err) {
        CASE(GL_INVALID_ENUM);
        CASE(GL_INVALID_VALUE);
        CASE(GL_INVALID_OPERATION);
        CASE(GL_INVALID_FRAMEBUFFER_OPERATION);
        CASE(GL_INVALID_INDEX);
        CASE(GL_OUT_OF_MEMORY);
    default:
        printf("\tError code not handled: %X", err);
    }
}

void _log_gl_errors(const char * file, int line) {
    GLenum err = glGetError();
    if(err != GL_NO_ERROR)
        _log_error(file, line, "Logging GL errors: ");
    while(err != GL_NO_ERROR){
        gl_err_str(err);
        err = glGetError();
    }
}
