#ifndef _KEYBINDINGS_SHARED_STRUCTS_H_
#define _KEYBINDINGS_SHARED_STRUCTS_H_

#include "../config.h"

typedef unsigned int keybind_index;
typedef unsigned short key_code_t;

struct keybind {
    keybind_index index;
    key_code_t keys[KEYSTROKE_MAX_SIZE];
};

#endif
