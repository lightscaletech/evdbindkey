#include "client_config.h"
#include "logging.h"
#include "signal.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <libevdev/libevdev.h>

#define CONF_FILENAME "binds_rc"

#define ITEMS_ALLOC_SIZE 10
#define LINE_SIZE 256

#define REGEX_TRIM          "(^[ \t]*)|([ \t]*$)"
#define REGEX_EMPTY_LINE    "^[ \t]*$"
#define REGEX_KEYBIND_SEP   "[ \t]*\\+[ \t]*"
#define REGEX_COMMAND_START "^[ \t]+"

enum read_status {
    STATUS_NOP,
    STATUS_KEYBINDS,
    STATUS_COMMAND,
};


struct config_regexs {
    regex_t empty_line;
    regex_t keybind_sep;
    regex_t command_start;
};

struct config_state {
    FILE * file;
    size_t capacity, amount, key_index;
    struct config_item * items;
    struct config_item item;
    enum read_status status;
    int next_line;
    struct config_regexs regex;
};

static int regex_init(struct config_regexs *);
static void regex_deinit(struct config_regexs *);

static int state_init(struct config_state *);
static void state_deinit(struct config_state *);
static int state_realloc_items(struct config_state *, size_t);
static int state_expand_items(struct config_state *);
static int state_compact_items(struct config_state *);
static int state_push_item(struct config_state *);


static int process_keybind_line(struct config_state *, char *);
static int process_command_line(struct config_state *, char *);
static int process_line(struct config_state *, char *);
static int read_lines(struct config_state *);

static struct config * config_from_state(struct config_state *);

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

int
regex_init(struct config_regexs * regx)
{
    int rc;

    rc = regcomp(&regx->empty_line, REGEX_EMPTY_LINE, REG_EXTENDED);
    if(rc != 0) return -1;

    rc = regcomp(&regx->keybind_sep, REGEX_KEYBIND_SEP, REG_EXTENDED);
    if(rc != 0) return -1;

    rc = regcomp(&regx->command_start, REGEX_COMMAND_START, REG_EXTENDED);
    if(rc != 0) return -1;

    return 0;
}

void
regex_deinit(struct config_regexs * regx)
{
    regfree(&regx->empty_line);
    regfree(&regx->keybind_sep);
    regfree(&regx->command_start);
}

int
state_init(struct config_state * state)
{
    state->amount = state->capacity = 0;
    state->capacity += ITEMS_ALLOC_SIZE;
    state->items = malloc(sizeof(struct config_state) * state->capacity);
    state->file = NULL;
    state->status = STATUS_NOP;
    state->next_line = 0;
    return regex_init(&state->regex);
}

void
state_deinit(struct config_state * state)
{
    regex_deinit(&state->regex);
    fclose(state->file);
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

int
state_push_item(struct config_state * state)
{
    int rc;
    if(state->amount == state->capacity) {
        rc = state_expand_items(state);
        if(rc < 0) return rc;
    }

    struct config_item * item;
    item = &state->items[state->amount++];

    *item = state->item;

    return 0;
}

static size_t
regex_match_all(regex_t * regex, char * text,
                size_t nmatch, regmatch_t * pmatch)
{
    int rc;
    size_t i, inc, count;
    char * buf = text;
    regmatch_t * curmatch;

    count = 0;
    rc = 0;

    for(i = 0; i < nmatch; ++i) {
        curmatch = &pmatch[i];
        curmatch->rm_so = curmatch->rm_eo = -1;

        if(rc == 0) {
            rc = regexec(regex, buf, 1, curmatch, 0);
        }
        if(rc == 0) {
            inc = curmatch->rm_eo;
            curmatch->rm_so += buf - text;
            curmatch->rm_eo += buf - text;
            buf += inc;
            count++;
        }
    }

    return count;
}

static int
process_bind_key(struct config_state * state, char *key)
{
    int code;
    code = libevdev_event_code_from_name(EV_KEY, key);
    if(code < 0) return -1;
    state->item.keys[state->key_index++] = code;
    return 0;
}

int
process_keybind_line(struct config_state * state, char * line)
{
    const size_t max_key_size = 25;
    size_t nmatch = 5, count, i, key_size;
    regmatch_t matches[nmatch];
    regmatch_t * match;
    char * key_start = line;
    char key[max_key_size];
    int rc;

    state->key_index = 0;
    memset(state->item.keys, 0, sizeof(state->item.keys));

    count = regex_match_all(&state->regex.keybind_sep, line, nmatch, matches);
    for(i = 0; i < count; ++i) {
        match = &matches[i];
        key_size = match->rm_so - (key_start - line);
        if(key_size + 1 > max_key_size) {
            log_error("Key too big");
            return -1;
        }
        strncpy(key, key_start, key_size);
        key[key_size] = '\0';
        rc = process_bind_key(state, key);
        if(rc < 0) return rc;
        key_start = line + match->rm_eo;
    }

    key_size = strlen(key_start) + 1;
    if(key_size > max_key_size) {
        log_error("Key too big");
        return -1;
    }
    else {
        strncpy(key, key_start, max_key_size);
        rc = process_bind_key(state, key);
        if(rc < 0) return rc;
    }

    if(!state->next_line) {
        state->status = STATUS_COMMAND;
    }

    return 0;
}

int
process_command_line(struct config_state * state, char * line)
{
    regmatch_t match;
    int rc;

    rc = regexec(&state->regex.command_start, line, 1, &match, 0);
    if(rc != 0) return -1;

    line += match.rm_eo;
    state->item.cmd = malloc(sizeof(char) * (strlen(line) + 1));
    strcpy(state->item.cmd, line);

    if(!state->next_line) {
        state_push_item(state);
        state->status = STATUS_NOP;
    }

    return 0;
}

int
process_line(struct config_state * state, char * line)
{
    char * ch;
    int rc, next_line;

    next_line = 0;
    ch = strchr(line, '\n');
    if(ch != NULL) *ch = '\0';
    if((ch - 1) >= line && *(ch - 1) == '\\') {
        *ch = '\0';
        next_line = 1;
    }

    ch = strchr(line, '#');
    if(ch != NULL) *ch = '\0';

    rc = regexec(&state->regex.empty_line, line, 0, NULL, 0);
    if(rc == 0) return 0;

    switch(state->status) {
    case STATUS_NOP:
    case STATUS_KEYBINDS: rc = process_keybind_line(state, line); break;
    case STATUS_COMMAND:  rc = process_command_line(state, line); break;
    }

    if(rc < 0) return rc;

    state->next_line = next_line;

    return 0;
}

int
read_lines(struct config_state * state)
{
    int rc;
    char line[LINE_SIZE];
    char *res;
    size_t lnum;

    lnum = 0;

    while( signal_running ) {
        lnum++;
        res = fgets(line, LINE_SIZE, state->file);
        if(res == NULL) break;

        if(strchr(line, '\n') == NULL) {
            log_error("Config line %i is longer than max length (%i)",
                      lnum, LINE_SIZE);
            return -1;
        }

        rc = process_line(state, line);
        if(rc < 0) return -1;
    }

    if(!signal_running) return -1;

    return 0;
}

struct config *
config_from_state(struct config_state * state)
{
    struct config * config;

    config = malloc(sizeof(struct config));

    config->items = state->items;
    config->items_count = state->amount;

    return config;
}

struct config *
config_read()
{
    struct config_state state;
    int rc;

    rc = state_init(&state);
    if(rc < 0) return NULL;

    state.file = open_config();
    if(state.file == NULL) return NULL;

    rc = read_lines(&state);
    if(rc < 0) return NULL;

    rc = state_compact_items(&state);
    if(rc < 0) return NULL;

    state_deinit(&state);

    return config_from_state(&state);
}

void
config_free(struct config * config)
{
    for(size_t i = 0; i < config->items_count; ++i) {
        if(config->items[i].cmd)
            free(config->items[i].cmd);
    }
    free(config->items);
    free(config);
}
