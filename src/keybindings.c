#include "ipc_sock.h"
#include "signal.h"
#include "shared_structs.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <libevdev/libevdev.h>

#define LENGTH(X)               (sizeof X / sizeof X[0])
#define END(A)                  ((A) + LENGTH(A))

enum status {
    STATUS_WAIT_READY    = 0x1,
    STATUS_READY         = 0x2,
    STATUS_SEND_KEYBIND  = 0x4,
    STATUS_WAIT_RECV     = 0x8,

    STATUS_ERR           = 0x80
};

struct socket {
    int fd;
};

static struct socket * socket_new();
static void socket_free(struct socket *);

static int send_key_binds(int);
static int handle_message(int);
static void start_polling(struct socket *);

struct keybind binds[] = {
    {.index = 0, .keys = { KEY_LEFTCTRL, KEY_LEFTALT, KEY_LEFTSHIFT, KEY_L, 0, 0}},
    {.index = 1, .keys = { KEY_LEFTCTRL, KEY_LEFTALT, KEY_LEFTSHIFT, KEY_D, 0, 0}},
    {.index = 2, .keys = { KEY_VOLUMEDOWN, 0, 0, 0, 0, 0}},
    {.index = 3, .keys = { KEY_VOLUMEUP, 0, 0, 0, 0, 0}},
    {.index = 4, .keys = { KEY_MUTE, 0, 0, 0, 0, 0}},
};

struct socket *
socket_new()
{
    struct sockaddr_un name;
    struct socket * sock;
    int rc;

    sock = malloc(sizeof(struct socket));
    if(sock == NULL) return sock;

    sock->fd = ipc_sock_new(&name);
    if(sock < 0) return NULL;

    rc = connect(sock->fd, (struct sockaddr *) &name, sizeof(name));
    if(rc < 0) return NULL;

    return sock;
}

void
socket_free(struct socket * sock)
{
    close(sock->fd);
    free(sock);
}

int
send_key_binds(int fd)
{
    int rc;
    ipc_size amount;
    size_t buf_size = 254;
    char buf[buf_size];

    amount = sizeof(binds) / sizeof(struct keybind);

    rc = ipc_write_msg(fd, IPC_MSG_BIND);
    if(rc < 0) return rc;

    rc = write(fd, &amount, sizeof(amount));
    if(rc < 0) return rc;

    rc = write(fd, &binds, sizeof(binds));
    if(rc < 0) return rc;

    rc = ipc_read_timeout(fd, &buf, buf_size);
    if(rc < 0) return rc;

    if(ipc_test_msg(buf, IPC_MSG_RECV)) {
        return 0;
    }

    return -1;
}

static void
run_keybind(int fd)
{
    keybind_index index;
    int rc;

    rc = ipc_read_timeout(fd, &index, sizeof(keybind_index));
    if(rc < 0) return;

    log_info("trigger: %i", index);
}

int
handle_message(int fd)
{
    const size_t bufsize = 256;
    char buf[bufsize];

    read(fd, &buf, bufsize);
    if(ipc_test_msg(buf, IPC_MSG_READY)) {
        log_info("READY");
        return send_key_binds(fd);
    }

    if(ipc_test_msg(buf, IPC_MSG_TRIG)) {
        run_keybind(fd);
    }

    return 0;
}

void
start_polling(struct socket * sock)
{
    int rc;
    struct pollfd pfds[1];
    struct pollfd * pfd = &pfds[0];

    pfd->fd = sock->fd;
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

        rc = handle_message(pfd->fd);
        if(rc < 0) break;
    }
}

int main(int argi, char** argv) {
    int rc;
    struct socket * sock;

    rc = signal_setup_actions();
    if(rc < 0) {
        perror("Failed to setup signals");
        exit(-1);
    }

    sock = socket_new();
    if(sock == NULL) {
        perror("Failed to open IPC socket");
        exit(-1);
    }

    start_polling(sock);

    socket_free(sock);

    return 0;
}
