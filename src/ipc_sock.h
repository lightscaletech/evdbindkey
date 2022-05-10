#ifndef KEYBINDINGS_IPC_SOCK
#define KEYBINDINGS_IPC_SOCK

struct sockaddr_un;

int ipc_sock_new(struct sockaddr_un *);
void ipc_sock_free(int);

#endif
