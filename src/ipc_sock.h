#ifndef _KEYBINDINGS_IPC_SOCK_H_
#define _KEYBINDINGS_IPC_SOCK_H_

#define IPC_TIMEOUT_MS 1000
#define IPC_MSG_READY "ready"
#define IPC_MSG_BIND  "bind"
#define IPC_MSG_RECV  "recv"

#include <unistd.h>

typedef size_t ipc_size;

struct sockaddr_un;

int ipc_sock_new(struct sockaddr_un *);
void ipc_sock_free(int);

int ipc_read_timeout_m(int, void *, size_t, unsigned long);
int ipc_read_timeout(int, void *, size_t);
ssize_t ipc_write_msg(int, char *);
int ipc_test_msg(char * str, char * msg);

#endif
