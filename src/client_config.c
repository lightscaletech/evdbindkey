#include "client_config.h"
#include "../config.h"
#include "shared_structs.h"
#include "logging.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>

#define CONF_FILENAME "binds.conf"

#define ITEMS_ALLOC_SIZE 10


struct config_item {
    key_code_t keys[KEYSTROKE_MAX_SIZE];
    char * cmd;
};

struct config_state {
    size_t capacity, amount;
    struct config_item * items;
    FILE * file;
};

static void state_init(struct config_state *);
static int state_realloc_items(struct config_state *, size_t);
static int state_expand_items(struct config_state *);
static int state_compact_items(struct config_state *);
static int state_add_item(struct config_state *, struct config_item *);

static FILE * open_config();

FILE *
open_config()
{
    char * base_path;
    char * path;
    char path_part[strlen(CONF_FILENAME) + strlen(PACKAGE) + 3];
    FILE * file;

    file = NULL;
    sprintf(path_part, "/%s/%s", PACKAGE, CONF_FILENAME);

    if((base_path = getenv("XDG_CONFIG_HOME"))) {
        path = malloc(sizeof(char) * (strlen(path_part) + strlen(base_path) + 1));
        sprintf(path, "%s%s", base_path, path_part);
        file = fopen(path, "r");
        if(file) log_info("Using config: %s", path);
        free(path);
        if(file) return file;
    }

    if((base_path = getenv("HOME")) != NULL) {
        const char dir[] = "/.config";
        path = malloc(sizeof(char) * (strlen(base_path) + strlen(path_part) + strlen(dir) + 1));
        sprintf(path, "%s%s%s", base_path, dir, path_part);
        file = fopen(path, "r");
        if(file) log_info("Using config: %s", path);
        free(path);
    }

    return file;
}

void
state_init(struct config_state * state)
{
    state->amount = state->capacity = 0;
    state->capacity += ITEMS_ALLOC_SIZE;
    state->items = malloc(sizeof(struct config_state) * state->capacity);
    state->file = NULL;
}

int
state_realloc_items(struct config_state * state, size_t capacity_new)
{
    struct config_item * items_new;

    state->capacity += capacity_new;
    items_new = realloc(state->items, sizeof(struct config_state) * state->capacity);
    if(items_new != NULL) {
        state->items = items_new;
        return 0;
    }
    return -1;
}

int
state_expand_items(struct config_state * state)
{
    return state_realloc_items(state, state->capacity + ITEMS_ALLOC_SIZE);
}

int
state_compact_items(struct config_state * state)
{
    return state_realloc_items(state, state->amount);
}

int state_add_item(struct config_state * state, struct config_item * item_new)
{
    int rc;
    if(state->amount == state->capacity) {
        rc = state_expand_items(state);
        if(rc < 0) return rc;
    }

    struct config_item * item;
    item = &state->items[state->amount++];

    *item = *item_new;

    return 0;
}

struct config_item *
read_config()
{
    struct config_state state;

    state_init(&state);

    state.file = open_config();
    if(state.file == NULL) return NULL;

    // TODO: handle return
    state_compact_items(&state);

    return state.items;
}
