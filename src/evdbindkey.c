#include "ipc_sock.h"
#include "signal.h"
#include "shared_structs.h"
#include "client_config.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <libevdev/libevdev.h>

struct socket {
    int fd;
};

struct state {
    struct socket * sock;
    struct keybind * keybinds;
    char ** cmds;
    size_t binds_count;
};

static struct socket * socket_new();
static void socket_free(struct socket *);

static void state_load_config(struct state *, struct config *);
static void state_free_keybinds(struct state *);
static void state_cleanup(struct state *);

static void run_cmd(char *);
static void run_keybind(struct state *);
static int send_key_binds(struct state *);
static int handle_message(struct state *);
static void start_polling(struct state *);

struct socket *
socket_new()
{
    struct sockaddr_un name;
    struct socket * sock;
    int rc;

    sock = malloc(sizeof(struct socket));
    if(sock == NULL) return sock;

    sock->fd = ipc_sock_new(&name);
    if(sock < 0) {
        free(sock);
        return NULL;
    }

    rc = connect(sock->fd, (struct sockaddr *) &name, sizeof(name));
    if(rc < 0) {
        free(sock);
        return NULL;
    }

    return sock;
}

void
socket_free(struct socket * sock)
{
    close(sock->fd);
    free(sock);
}

void
state_load_config(struct state * state, struct config * conf)
{
    struct keybind * bind;
    struct config_item * conf_item;
    state->binds_count = conf->items_count;
    state->keybinds = malloc(sizeof(struct keybind) * state->binds_count);
    state->cmds = malloc(sizeof(char **) * state->binds_count);
    for(size_t i = 0; i < state->binds_count; ++i) {
        bind = &state->keybinds[i];
        conf_item = &conf->items[i];
        bind->index = i;
        memcpy(bind->keys, conf_item->keys, sizeof(bind->keys));
        state->cmds[i] = conf_item->cmd;
        conf_item->cmd = NULL;
    }
}

void
state_free_keybinds(struct state * state)
{
    if(state->keybinds) {
        free(state->keybinds);
        state->keybinds = NULL;
    }
}

void
state_cleanup(struct state * state)
{
    for(size_t i = 0; i < state->binds_count; ++i) {
        free(state->cmds[i]);
    }
    free(state->cmds);

    state_free_keybinds(state);
}

int
send_key_binds(struct state * state)
{
    int rc, fd;
    ipc_size amount;
    size_t buf_size = 254;
    char buf[buf_size];

    fd = state->sock->fd;
    amount = state->binds_count;

    rc = ipc_write_msg(fd, IPC_MSG_BIND);
    if(rc < 0) return rc;

    rc = write(fd, &amount, sizeof(amount));
    if(rc < 0) return rc;

    rc = write(fd, state->keybinds, sizeof(struct keybind) * amount);
    if(rc < 0) return rc;

    rc = ipc_read_timeout(fd, &buf, buf_size);
    if(rc < 0) return rc;

    if(ipc_test_msg(buf, IPC_MSG_RECV)) {
        state_free_keybinds(state);
        return 0;
    }

    return -1;
}

void
run_cmd(char * cmd)
{
    pid_t pid = -1;

    pid = fork();
    if(pid == 0) {
        setsid();
        if(fork() == 0) {
            execlp("sh", "sh", "-c", cmd, NULL);
        }
        else _exit(0);
    }
    else if(pid > 0) wait(NULL);
}

void
run_keybind(struct state * state)
{
    keybind_index index;
    int rc, fd;

    fd = state->sock->fd;

    rc = ipc_read_timeout(fd, &index, sizeof(keybind_index));
    if(rc < 0) return;

    if(index >= 0 && index < state->binds_count) {
        run_cmd(state->cmds[index]);
    }
}

int
handle_message(struct state * state)
{
    const size_t bufsize = 256;
    char buf[bufsize];

    read(state->sock->fd, &buf, bufsize);
    if(ipc_test_msg(buf, IPC_MSG_READY)) {
        log_info("READY");
        return send_key_binds(state);
    }

    if(ipc_test_msg(buf, IPC_MSG_TRIG)) {
        run_keybind(state);
    }

    return 0;
}

void
start_polling(struct state * state)
{
    int rc;
    struct pollfd pfds[1];
    struct pollfd * pfd = &pfds[0];

    pfd->fd = state->sock->fd;
    pfd->events = POLLIN;

    while(signal_running) {
        rc = poll(pfds, 1, -1);

        if(rc < 0) {
            log_error("Poll failed");
            break;
        }
        if(rc == 0) continue; // timeout

        if(pfd->revents & POLLHUP ||
           pfd->revents & POLLERR ||
           pfd->revents & POLLNVAL) {
            log_error("Sock shutdown");
            break;
        }

        rc = handle_message(state);
        if(rc < 0) break;
    }
}

int main(int argi, char** argv) {
    int rc;
    struct config * config;
    struct state state;

    rc = signal_setup_actions();
    if(rc < 0) {
        perror("Failed to setup signals");
        exit(-1);
    }

    config = config_read();
    if(config == NULL) {
        perror("Failed to read config");
        exit(-1);
    }

    state_load_config(&state, config);
    config_free(config);

    state.sock = socket_new();
    if(state.sock == NULL) {
        perror("Failed to open IPC socket");
        exit(-1);
    }

    start_polling(&state);

    socket_free(state.sock);
    state_cleanup(&state);

    return 0;
}
