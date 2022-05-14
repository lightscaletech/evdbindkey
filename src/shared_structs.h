#ifndef _KEYBINDINGS_SHARED_STRUCTS_H_
#define _KEYBINDINGS_SHARED_STRUCTS_H_

#include "../config.h"

struct keybind {
    unsigned int index;
    unsigned short keys[KEYSTROKE_MAX_SIZE];
};

#endif
