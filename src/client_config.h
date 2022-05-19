#ifndef _KEYBINDINGS_CLIENT_CONFIG_H_
#define _KEYBINDINGS_CLIENT_CONFIG_H_

#include "../config.h"
#include "shared_structs.h"

#include <stddef.h>

struct config_item {
    key_code_t keys[KEYSTROKE_MAX_SIZE];
    char * cmd;
};

struct config {
    size_t items_count;
    struct config_item * items;
};


struct config * config_read();
void config_free(struct config *);

#endif
