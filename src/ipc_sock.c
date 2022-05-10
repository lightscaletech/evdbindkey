#include "ipc_sock.h"

#include "config.h"

#include <stdio.h>
#include <string.h>
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
