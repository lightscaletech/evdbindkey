#include "../config.h"
#include "ipc_sock.h"
#include "signal.h"
#include "shared_structs.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <libudev.h>
#include <libevdev/libevdev.h>

#define POLLFD_INDEX_SOCK 0
#define POLLFD_INDEX_MONITOR 1

// STRUCS

struct device {
    int fd;
    char * name;
    struct libevdev *evdev;
    key_code_t keys[KEYSTROKE_MAX_SIZE];
};

struct devices {
    size_t count;
    struct udev * udev;
    struct udev_monitor * monitor;
    struct device ** data;
};

struct client {
    int fd;
    size_t keybinds_count;
    struct keybind *keybinds;
};

struct socket {
    int fd;
    size_t clients_count;
    struct client **clients;
};

struct pollfds_layout {
    size_t devices_start, devices_end;
    size_t clients_start, clients_end;
    size_t count;
    struct pollfd * pfds;
};

// FUNCTION DEFINITIONS
static struct device * device_new(const char * path);
static void device_free(struct device *);

static int devices_init(struct devices *);
static int devices_add(struct devices *, struct device *);
static struct device * devices_find_by_fd(struct devices *, int);
static int devices_index_from_name(struct devices *, const char *);
static void devices_remove(struct devices *, int);

static struct client * client_new();
static void client_free(struct client *);

static struct socket * socket_new();
static void socket_free(struct socket *);
static int socket_client_add(struct socket *, struct client *);
static int socket_client_index_from_fd(struct socket *, int);
static void socket_client_remove(struct socket *, int);

static struct pollfds_layout * pollfds_layout_create(struct devices *,
                                                     struct socket *);
static void pollfds_layout_free(struct pollfds_layout *);
static struct pollfds_layout * pollfds_layout_recreate(struct pollfds_layout *,
                                                       struct devices *,
                                                       struct socket *);

static void find_devices(struct devices *);

static void start_polling(struct devices *, struct socket *);

static struct pollfds_layout * handle_poll_events(struct pollfds_layout *,
                                                  struct devices *,
                                                  struct socket *);

static struct pollfds_layout * handle_new_connection(
    struct pollfds_layout *, struct devices *, struct socket *
);

static struct pollfds_layout * handle_udev_monitor(struct pollfds_layout *,
                                                   struct devices *,
                                                   struct socket *);

static void handle_client_bind_keys(int client_index, struct socket * sock);

static struct pollfds_layout * handle_client_events(struct pollfd * pfd,
                                                    struct pollfds_layout * pfdsl,
                                                    struct devices * devices,
                                                    struct socket * sock);


static void handle_key(struct device * device, struct socket * sock,
                       struct input_event * ev);
static void handle_device_event(struct pollfd * pfd, struct devices * devices,
                                struct socket * sock);

// IMPLEMENTATION

struct device *
device_new(const char * path)
{
    size_t size;
    struct device * dev;
    int rc;

    size = sizeof(struct device);
    dev = (struct device *) malloc(size);
    memset(dev, 0, size);

    size = strlen(path) + 1;
    dev->name = malloc(size);
    strncpy(dev->name, path, size);

    log_debug("name: %s", dev->name);

    dev->fd = open(path, O_RDONLY | O_NONBLOCK);
    if(dev->fd < 0) {
        log_error("Failed to device: %s", path);
        perror("");
        free(dev);
        return NULL;
    }

    rc = libevdev_new_from_fd(dev->fd, &dev->evdev);
    if(rc < 0) {
        log_error("Filed to create libevdev device: %s", path);
        close(dev->fd);
        free(dev);
        return NULL;
    }

    log_info("Input device name: (%i) \"%s\"",
             dev->fd,
             libevdev_get_name(dev->evdev));
    log_info("Input device ID: bus %#x vendor %#x product %#x",
             libevdev_get_id_bustype(dev->evdev),
             libevdev_get_id_vendor(dev->evdev),
             libevdev_get_id_product(dev->evdev));

    return dev;
}

void
device_free(struct device * dev)
{
    libevdev_free(dev->evdev);
    close(dev->fd);
    free(dev->name);
    free(dev);
}

int
devices_init(struct devices * devices)
{
    int rc;

    devices->udev = udev_new();
    if(devices->udev == NULL) return -1;

    devices->monitor = udev_monitor_new_from_netlink(devices->udev, "udev");
    if(devices->monitor == NULL) return -1;

    rc = udev_monitor_filter_add_match_subsystem_devtype(devices->monitor, "input", NULL);
    if(rc < 0) {
        udev_monitor_unref(devices->monitor);
        udev_unref(devices->udev);
        return rc;
    }

    rc = udev_monitor_enable_receiving(devices->monitor);
    if(rc < 0) {
        udev_monitor_unref(devices->monitor);
        udev_unref(devices->udev);
        return rc;
    }

    devices->count = 0;
    devices->data = NULL;

    return 0;
}

void
devices_cleanup(struct devices * devices)
{
    udev_monitor_unref(devices->monitor);
    udev_unref(devices->udev);

    for(size_t i = 0; i < devices->count; ++i) {
        device_free(devices->data[i]);
    }

    free(devices->data);
}

struct device *
devices_find_by_fd(struct devices * devices, int fd)
{
    for(size_t i = 0; i < devices->count; ++i) {
        if(devices->data[i]->fd == fd) return devices->data[i];
    }
    return NULL;
}

int
devices_index_from_name(struct devices * devices, const char * name)
{
    const char * n;
    for(size_t i = 0; i < devices->count; ++i) {
        n = devices->data[i]->name;
        if(strncmp(n, name, strlen(n)) == 0) return i;
    }
    return -1;
}

int
devices_add(struct devices * devices, struct device * device)
{
    struct device ** devarr;
    const size_t size = sizeof(struct device *);

    if(devices->data == NULL && devices->count == 0)
        devarr = malloc(size * ++devices->count);
    else devarr = realloc(devices->data, size * ++devices->count);

    if(devarr) {
        devarr[devices->count - 1] = device;
        devices->data = devarr;
        return 0;
    }

    return -1;
}

void
devices_remove(struct devices * devices, int index)
{
    size_t i;
    struct device ** devarr = NULL;
    size_t * count = &devices->count;

    device_free(devices->data[index]);

    for(i = index; i < devices->count - 1; ++i) {
        devices->data[i] = devices->data[i + 1];
    }
    --*count;
    if(*count == 0) {
        free(devices->data);
        devices->data = NULL;
    }
    else devarr = realloc(devices->data, sizeof(struct device *) * *count);
    if(devarr) devices->data = devarr;
}

void
find_devices(struct devices *devices)
{
    struct udev_enumerate * enumerate = udev_enumerate_new(devices->udev);

    udev_enumerate_add_match_is_initialized(enumerate);
    udev_enumerate_add_match_subsystem(enumerate, "input");
    udev_enumerate_add_match_property(enumerate, "ID_INPUT_KEYBOARD", "1");
    udev_enumerate_scan_devices(enumerate);

    struct udev_list_entry * found = 0;
    found = udev_enumerate_get_list_entry(enumerate);

    struct udev_list_entry * entry = 0;
    struct udev_device *udevice = 0;
    struct device *dev = 0;
    const char *devpath, *nodepath;
    int rc;

    udev_list_entry_foreach(entry, found) {
        devpath = udev_list_entry_get_name(entry);
        udevice = udev_device_new_from_syspath(devices->udev, devpath);
        nodepath = udev_device_get_devnode(udevice);
        if(nodepath) {
            dev = device_new(nodepath);

            if(dev) {
                rc = devices_add(devices, dev);
                if(rc < 0) {
                    device_free(dev);
                }
            }
        }
        udev_device_unref(udevice);
    }

    udev_enumerate_unref(enumerate);
}

struct client *
client_new(int fd)
{
    struct client * client = malloc(sizeof(struct client));

    if(client) {
        client->fd = fd;
        client->keybinds_count = 0;
        client->keybinds = NULL;
    }

    return client;
}

void
client_free(struct client * client)
{
    close(client->fd);
    free(client->keybinds);
    free(client);
}

struct socket *
socket_new()
{
    struct socket * sock = malloc(sizeof(struct socket));
    struct sockaddr_un name;
    int rc;

    // TODO: if steals a from running instance then the other instance should
    // gracefully shutdown
    rc = unlink(IPC_SOCK_PATH);
    if(rc < 0 && errno != ENOENT) {
        return NULL;
    }

    sock->fd = ipc_sock_new(&name);
    sock->clients_count = 0;
    sock->clients = NULL;

    rc = bind(sock->fd, (const struct sockaddr *) &name, sizeof(name));
    if(rc < 0) {
        free(sock);
        return NULL;
    }

    rc = chmod(name.sun_path, S_IRWXU | S_IRWXG | S_IRWXO);

    rc = listen(sock->fd, 10);
    if(rc < 0) {
        socket_free(sock);
        return NULL;
    }

    return sock;
}

void
socket_free(struct socket *sock)
{
    for(size_t i = 0; i < sock->clients_count; ++i) {
        client_free(sock->clients[i]);
    }

    if(sock->clients_count > 0) free(sock->clients);

    close(sock->fd);
    unlink(IPC_SOCK_PATH);
    free(sock);
}

int
socket_client_add(struct socket * sock, struct client * client)
{
    struct client ** arr;
    size_t size = sizeof(struct client *);

    if(sock->clients_count == 0 && sock->clients == NULL) {
        arr = malloc(size * ++sock->clients_count);
    }
    else {
        arr = realloc(sock->clients, size * ++sock->clients_count);
    }

    if(arr) {
        arr[sock->clients_count - 1] = client;
        sock->clients = arr;
        return 0;
    }

    return -1;
}

int
socket_client_index_from_fd(struct socket * sock, int fd)
{
    for(size_t i = 0; i < sock->clients_count; ++i) {
        if(sock->clients[i]->fd == fd) return i;
    }
    return -1;
}

void
socket_client_remove(struct socket * sock, int index)
{
    size_t i;
    struct client ** devarr = NULL;

    client_free(sock->clients[index]);

    for(i = index; i < sock->clients_count - 1; ++i) {
        sock->clients[i] = sock->clients[i + 1];
    }
    --sock->clients_count;
    if(sock->clients_count == 0) {
        free(sock->clients);
        sock->clients = NULL;
    }
    else {
        devarr = realloc(sock->clients, sizeof(struct device *) * sock->clients_count);
    }
    if(devarr) sock->clients = devarr;
}


struct pollfds_layout *
pollfds_layout_create(struct devices * devices, struct socket * sock)
{
    const size_t offset = 2;
    struct pollfds_layout * pfdsl;
    struct pollfd * pfds;
    size_t i = 0;

    pfdsl = (struct pollfds_layout *) malloc(sizeof(struct pollfds_layout));

    // make it bigger with offset for ipc sock and udev monitor
    pfdsl->count = offset + devices->count + sock->clients_count;
    pfdsl->devices_start = offset;
    pfdsl->devices_end = pfdsl->devices_start + devices->count;
    pfdsl->clients_start = pfdsl->devices_end;
    pfdsl->clients_end = pfdsl->clients_start + sock->clients_count;

    pfds = (struct pollfd *) malloc(sizeof(struct pollfd) * pfdsl->count);

    // add ipc sock
    pfds[POLLFD_INDEX_SOCK].fd = sock->fd;
    pfds[POLLFD_INDEX_SOCK].events = POLLIN;

    // add udev monitor sock
    pfds[POLLFD_INDEX_MONITOR].fd = udev_monitor_get_fd(devices->monitor);
    pfds[POLLFD_INDEX_MONITOR].events = POLLIN;

    // add devices
    for(i = pfdsl->devices_start; i < pfdsl->devices_end; ++i) {
        pfds[i].fd = devices->data[i - pfdsl->devices_start]->fd;
        pfds[i].events = POLLIN;
    }

    // add ipc clients
    for(i = pfdsl->clients_start; i < pfdsl->clients_end; ++i) {
        pfds[i].fd = sock->clients[i - pfdsl->clients_start]->fd;
        pfds[i].events = POLLIN;
    }

    pfdsl->pfds = pfds;

    return pfdsl;
}

void
pollfds_layout_free(struct pollfds_layout * pfdsl)
{
    free(pfdsl->pfds);
    log_debug("pfdsl free: %i", pfdsl);
    free(pfdsl);
}

struct pollfds_layout *
pollfds_layout_recreate(struct pollfds_layout * pfdsl,
                        struct devices * devices,
                        struct socket * sock)
{
    pollfds_layout_free(pfdsl);
    return pollfds_layout_create(devices, sock);
}

static void
keybind_trigger(struct client * client, int i)
{
    keybind_index index;
    index = client->keybinds[i].index;
    ipc_write_msg(client->fd, IPC_MSG_TRIG);
    write(client->fd, &index, sizeof(index));
}

static int
find_key(key_code_t * keys, key_code_t key)
{
    for(size_t i = 0; i < KEYSTROKE_MAX_SIZE; ++i)
        if(keys[i] == key) return i;

    return -1;
}

static int
check_keys_match_keybind(key_code_t * keys, key_code_t * keybind)
{
    size_t i;
    int rc;
    key_code_t k;
    for(i = 0; i < KEYSTROKE_MAX_SIZE; ++i) {
        k = keybind[i];
        rc = find_key(keys, k);
        if(rc < 0) return 0;
    }
    return 1;
}

static void
check_keys_match_clients(key_code_t * keys, struct socket * sock)
{
    size_t ic, ik;
    int rc;
    struct client * client;
    struct keybind * keybind;
    for(ic = 0; ic < sock->clients_count; ++ic) {
        client = sock->clients[ic];
        for(ik = 0; ik < client->keybinds_count; ++ik) {
            keybind = &client->keybinds[ik];
            rc = check_keys_match_keybind(keys, keybind->keys);
            if(rc) keybind_trigger(client, ik);
        }
    }
}

static int
find_empty_key(key_code_t * keys)
{
    for(size_t i = 0; i < KEYSTROKE_MAX_SIZE; ++i)
        if(keys[i] == 0) return i;

    return -1;
}

void
handle_key(struct device * device,
           struct socket * sock,
           struct input_event * ev)
{
    int rc;

    if(ev->type == EV_KEY && (ev->value == 0 || ev->value == 1)) {
        if(ev->value == 0) {
            rc = find_key(device->keys, ev->code);
            if(rc >= 0) device->keys[rc] = 0;
        }
        else if(ev->value == 1) {
            rc = find_key(device->keys, ev->code);
            if(rc >= 0) return;
            rc = find_empty_key(device->keys);
            if(rc >= 0) device->keys[rc] = ev->code;
        }
        check_keys_match_clients(device->keys, sock);
    }
}

void
handle_device_event(struct pollfd * pfd,
                    struct devices * devices,
                    struct socket * sock)
{
    int rc;
    unsigned int evflag;
    struct device * device = 0;
    struct input_event ev;

    device = devices_find_by_fd(devices, pfd->fd);
    if(device == NULL) return;

    rc = LIBEVDEV_READ_STATUS_SUCCESS;
    do {
        evflag = (rc == LIBEVDEV_READ_STATUS_SYNC ?
                  LIBEVDEV_READ_FLAG_SYNC :
                  LIBEVDEV_READ_FLAG_NORMAL);

        rc = libevdev_next_event(device->evdev, evflag, &ev);
        if(rc == LIBEVDEV_READ_STATUS_SUCCESS) {
            handle_key(device, sock, &ev);
        }
    } while(rc == LIBEVDEV_READ_STATUS_SUCCESS ||
            rc == LIBEVDEV_READ_STATUS_SYNC);
}

struct pollfds_layout *
handle_new_connection(struct pollfds_layout * pfdsl,
                      struct devices * devices,
                      struct socket * sock)
{
    int fd;

    fd = accept(sock->fd, NULL, NULL);
    if(fd < 0) return pfdsl;

    log_info("New IPC connection: %i", fd);

    struct client * client = client_new(fd);
    socket_client_add(sock, client);

    ipc_write_msg(fd, IPC_MSG_READY);

    return pollfds_layout_recreate(pfdsl, devices, sock);
}

struct pollfds_layout *
handle_udev_monitor(struct pollfds_layout * pfdsl,
                    struct devices * devices,
                    struct socket * sock)
{
    struct udev_device * udevice;
    struct device * device;
    const char * prop, * nodepath, * action;

    udevice = udev_monitor_receive_device(devices->monitor);

    nodepath = udev_device_get_devnode(udevice);
    if(nodepath == NULL) {
        udev_device_unref(udevice);
        return NULL;
    }

    prop = udev_device_get_property_value(udevice, "ID_INPUT_KEYBOARD");
    if(prop == NULL || strncmp(prop, "1", 1) != 0) {
        udev_device_unref(udevice);
        return NULL;
    }

    action = udev_device_get_property_value(udevice, "ACTION");
    if(!action) {
        udev_device_unref(udevice);
        return NULL;
    }

    if(strncmp(action, "add", strlen(action)) == 0) {
        log_debug("KEYBOARD ADD");
        device = device_new(nodepath);
        if(device != NULL) {
            devices_add(devices, device);
            udev_device_unref(udevice);
            return pollfds_layout_recreate(pfdsl, devices, sock);
        }
    }
    else if(strncmp(action, "remove", strlen(action)) == 0) {
        int i = devices_index_from_name(devices, nodepath);
        log_debug("KEYBOARD REMOVE: %i", i);
        if(i >= 0 ) {
            devices_remove(devices, i);
            udev_device_unref(udevice);
            return pollfds_layout_recreate(pfdsl, devices, sock);
        }
    }

    udev_device_unref(udevice);
    return NULL;
}

void
handle_client_bind_keys(int client_index, struct socket * sock)
{
    struct client * client = sock->clients[client_index];
    struct keybind * binds;
    int fd, rc;
    size_t kbsize;
    ipc_size amount;

    fd = client->fd;
    rc = ipc_read_timeout(fd, &amount, sizeof(amount));
    if(rc < 0 || amount < 0) return;

    binds = client->keybinds;
    kbsize = sizeof(struct keybind);

    if(binds == NULL) binds = malloc(kbsize * amount);
    else binds = realloc(binds, kbsize * (client->keybinds_count + amount));

    if(binds == NULL) return;

    client->keybinds = binds;
    client->keybinds_count += amount;

    // TODO: Handle byte size bigger that SSIZE_MAX
    rc = ipc_read_timeout(fd, binds, kbsize * amount);
    if(rc < 0) return;

    ipc_write_msg(fd, IPC_MSG_RECV);
}

struct pollfds_layout *
handle_client_events(struct pollfd * pfd,
                     struct pollfds_layout * pfdsl,
                     struct devices * devices,
                     struct socket * sock)
{
    size_t buf_s = 256;
    char buf[buf_s];
    int client_index;

    client_index = socket_client_index_from_fd(sock, pfd->fd);
    if(client_index < 0) return NULL;

    if(pfd->revents & POLLHUP) {
        log_debug("HANGUP %i", pfd->fd);
        socket_client_remove(sock, client_index);
        return pollfds_layout_recreate(pfdsl, devices, sock);
    }
    else if(pfd->revents > 0) {
        log_debug("DATA %i", pfd->fd);
        read(pfd->fd, &buf, buf_s);

        if(ipc_test_msg(buf, IPC_MSG_BIND)){
            handle_client_bind_keys(client_index, sock);
        }
    }

    return NULL;
}

struct pollfds_layout *
handle_poll_events(struct pollfds_layout * pfdsl,
                   struct devices * devices,
                   struct socket * sock)
{
    size_t i;
    struct pollfd * pfd;
    struct pollfds_layout * pfdsl_new = NULL;

    pfd = &pfdsl->pfds[POLLFD_INDEX_SOCK];
    if(pfd->revents > 0) {
        pfdsl_new = handle_new_connection(pfdsl, devices, sock);
        return pfdsl_new ? pfdsl_new : pfdsl;
    }

    pfd = &pfdsl->pfds[POLLFD_INDEX_MONITOR];
    if(pfd->revents > 0) {
        pfdsl_new = handle_udev_monitor(pfdsl, devices, sock);
        return pfdsl_new ? pfdsl_new : pfdsl;
    }

    for(i = pfdsl->devices_start; i < pfdsl->devices_end; ++i) {
        pfd = &pfdsl->pfds[i];
        if(pfd->revents > 0) {
            handle_device_event(pfd, devices, sock);
        }
    }

    for(i = pfdsl->clients_start; i < pfdsl->clients_end; ++i) {
        pfd = &pfdsl->pfds[i];
        if(pfd->revents > 0) {
            pfdsl_new = handle_client_events(pfd, pfdsl, devices, sock);
            return pfdsl_new ? pfdsl_new : pfdsl;
        }
    }

    return pfdsl;
}

void
start_polling(struct devices * devices, struct socket * sock)
{
    struct pollfds_layout * pfdsl;
    int rc;

    pfdsl = pollfds_layout_create(devices, sock);

    while(signal_running) {
        rc = poll(pfdsl->pfds, pfdsl->count, -1);

        if(rc < 0) break; // error
        if(rc == 0) continue; // timeout

        pfdsl = handle_poll_events(pfdsl, devices, sock);

        if(pfdsl == NULL) break;
    }

    if(pfdsl != NULL) pollfds_layout_free(pfdsl);
}

int
main(int argi, char** argv)
{
    int rc;
    struct devices devices;
    struct socket * sock;

    rc = signal_setup_actions();
    if(rc < 0) {
        perror("Failed to setup signals");
        exit(-1);
    }

    sock = socket_new();
    if(sock == NULL) {
        perror("Failed to create socket");
        exit(-1);
    }

    rc = devices_init(&devices);
    if(rc < 0) {
        socket_free(sock);
        perror("Failed to init devices structure");
        exit(-1);
    }

    find_devices(&devices);

    start_polling(&devices, sock);

    devices_cleanup(&devices);
    socket_free(sock);

    return 0;
}
