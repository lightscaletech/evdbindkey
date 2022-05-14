#include "ipc_sock.h"
#include "../config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

int
ipc_sock_new(struct sockaddr_un *name)
{
    int sock;

    sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if(sock < 0) return sock;

    memset(name, 0, sizeof(*name));

    name->sun_family = AF_UNIX;
    strncpy(name->sun_path, IPC_SOCK_PATH, sizeof(name->sun_path));

    return sock;
}

int
ipc_read_timeout_m(int fd, void *buf, size_t bufsize, unsigned long timeout)
{
    int rc;
    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN
    };

    rc = poll(&pfd, 1, timeout);
    if(rc < 0) return -1;
    if(rc == 0) return -2;

    return read(fd, buf, bufsize);;
}

int
ipc_read_timeout(int fd, void *buf, size_t bufsize)
{
    return ipc_read_timeout_m(fd, buf, bufsize, IPC_TIMEOUT_MS);
}


ssize_t
ipc_write_msg(int fd, char * msg)
{
    return write(fd, msg, strlen(msg) + 1);
}

int
ipc_test_msg(char * str, char * msg)
{
    return strncmp(str, msg, strlen(msg)) == 0 ? 1 : 0;
}
