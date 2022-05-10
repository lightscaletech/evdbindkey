#include "ipc_sock.h"
#include <sys/socket.h>
#include <sys/un.h>

int main(int argi, char** argv) {
    struct sockaddr_un name;

    int fd = ipc_sock_new(&name);

    connect(fd, (struct sockaddr *) &name, sizeof(name));

    return 0;
}
