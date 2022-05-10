#include "config.h"
#include "ipc_sock.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libudev.h>
#include <libevdev/libevdev.h>

#define POLLFD_INDEX_SOCK 0
#define POLLFD_INDEX_MONITOR 1

// STRUCS

struct device {
    int fd;
    struct libevdev *evdev;
};

struct devices {
    size_t count;
    struct udev * udev;
    struct udev_monitor * monitor;
    struct device ** data;
};

struct keybind {
    unsigned int id;
    unsigned short keys[6];
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

// GLOBALS
sig_atomic_t running = 1;

// FUNCTION DEFINITIONS
static struct device * device_new(const char * path);
static void device_free(struct device *);

static int devices_init(struct devices *);
static int devices_add(struct devices *, struct device *);
static struct device * devices_find_by_fd(struct devices *, int);

static struct client * client_new();
static void client_free(struct client *);

static struct socket * socket_new();
static void socket_free(struct socket *);
static int socket_add_client(struct socket *, struct client *);
static struct client * socket_find_client_by_id(struct socket *, int);

static struct pollfds_layout * pollfds_layout_create(struct devices*, struct socket *);
static void pollfds_layout_free(struct pollfds_layout *);

static void find_devices(struct devices *);

static void start_polling(struct devices *, struct socket *);
static void handle_poll_events(struct pollfds_layout *,
                               struct devices *,
                               struct socket *);
static struct pollfds_layout * handle_new_connection(
    struct pollfds_layout *, struct devices *, struct socket *
);

static void handle_key_event(struct pollfd *, struct devices *);


static void handle_signal_shutdown(int);
static int setup_signals();

// IMPLEMENTATION

struct device *
device_new(const char * path)
{
    struct device * dev = (struct device *) malloc(sizeof(struct device));
    int rc;

    dev->fd = open(path, O_RDONLY | O_NONBLOCK);
    if(dev->fd < 0) {
        printf("Filed to open: %s", path);
        free(dev);
        return 0;
    }

    rc = libevdev_new_from_fd(dev->fd, &dev->evdev);
    if(rc < 0) {
        printf("Filed to create libevdev device: %s", path);
        close(dev->fd);
        free(dev);
        return 0;
    }

    printf("Input device name: (%i) \"%s\"\n", dev->fd, libevdev_get_name(dev->evdev));
    printf("Input device ID: bus %#x vendor %#x product %#x\n",
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

    rc = udev_monitor_enable_receiving(devices->monitor);
    if(rc < 0) {
        udev_monitor_unref(devices->monitor);
        udev_unref(devices->udev);
        return rc;
    }

    devices->count = 0;
    devices->data = (struct device **) malloc(0);
    if(devices->data == NULL) return -1;

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
devices_add(struct devices * devices, struct device * device)
{
    struct device ** devarr;

    ++devices->count;
    devarr = realloc(devices->data, sizeof(struct device **) * devices->count);
    if(devarr) {
        devarr[devices->count - 1] = device;
        devices->data = devarr;
        return 0;
    }

    return -1;
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
    struct client * client = (struct client *) malloc(sizeof(struct client));

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
    free(client->keybinds);
    free(client);
}

struct socket *
socket_new()
{
    struct socket * sock = (struct socket *) malloc(sizeof(struct socket));
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
    sock->clients = (struct client **) malloc(0);

    rc = bind(sock->fd, (const struct sockaddr *) &name, sizeof(name));
    if(rc < 0) {
        free(sock);
        return NULL;
    }

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
    free(sock->clients);

    close(sock->fd);
    unlink(IPC_SOCK_PATH);
    free(sock);
}

int
socket_add_client(struct socket * sock, struct client * client)
{
    struct client ** arr;

    ++sock->clients_count;
    arr = (struct client **) realloc(
        sock->clients,
        sizeof(struct client **) * sock->clients_count);

    if(arr) {
        arr[sock->clients_count - 1] = client;
        sock->clients = arr;
        return 0;
    }

    return -1;
}

struct client *
socket_find_client_by_id(struct socket * sock, int fd)
{
    for(size_t i = 0; i < sock->clients_count; ++i) {
        if(sock->clients[i]->fd == fd) return sock->clients[i];
    }
    return NULL;
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
    pfdsl->devices_end = pfdsl->devices_start + (devices->count - 1);
    pfdsl->clients_start = pfdsl->devices_end + 1;
    pfdsl->clients_end = pfdsl->clients_start + (sock->clients_count - 1);

    pfds = (struct pollfd *) malloc(sizeof(struct pollfd) * pfdsl->count);

    // add ipc sock
    pfds[POLLFD_INDEX_SOCK].fd = sock->fd;
    pfds[POLLFD_INDEX_SOCK].events = POLLIN;

    // add udev monitor sock
    pfds[POLLFD_INDEX_MONITOR].fd = udev_monitor_get_fd(devices->monitor);
    pfds[POLLFD_INDEX_MONITOR].events = POLLIN;

    // add devices
    for(i = pfdsl->devices_start; i <= pfdsl->devices_end; ++i) {
        pfds[i].fd = devices->data[i - pfdsl->devices_start]->fd;
        pfds[i].events = POLLIN;
    }

    // add ipc clients
    for(i = pfdsl->clients_start; i <= pfdsl->clients_end; ++i) {
        pfds[i].fd = sock->clients[i - pfdsl->clients_start]->fd;
        pfds[i].events = POLLIN;
    }

    pfdsl->pfds = pfds;

    return pfdsl;
}

void
pollfds_layout_free(struct pollfds_layout *pfdsl)
{
    free(pfdsl->pfds);
    free(pfdsl);
}

static int
print_event(struct input_event *ev)
{
    if (ev->type == EV_SYN)
        printf("Event: time %ld.%06ld, ++++++++++++++++++++ %s +++++++++++++++\n",
               ev->input_event_sec,
               ev->input_event_usec,
               libevdev_event_type_get_name(ev->type));
    else
        printf("Event: time %ld.%06ld, type %d (%s), code %d (%s), value %d\n",
               ev->input_event_sec,
               ev->input_event_usec,
               ev->type,
               libevdev_event_type_get_name(ev->type),
               ev->code,
               libevdev_event_code_get_name(ev->type, ev->code),
               ev->value);
    return 0;
}

void
handle_key_event(struct pollfd *pfd, struct devices * devices)
{
    int rc;
    unsigned int evflag;
    struct device * current_device = 0;
    struct input_event ev;

    current_device = devices_find_by_fd(devices, pfd->fd);
    if(current_device == NULL) return;

    rc = LIBEVDEV_READ_STATUS_SUCCESS;
    do {
        evflag = (rc == LIBEVDEV_READ_STATUS_SYNC ?
                  LIBEVDEV_READ_FLAG_SYNC :
                  LIBEVDEV_READ_FLAG_NORMAL);

        rc = libevdev_next_event(current_device->evdev, evflag, &ev);
        if(rc == LIBEVDEV_READ_STATUS_SUCCESS) {
            print_event(&ev);
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

    printf("New IPC connection: %i\n", fd);

    struct client * client = client_new(fd);
    socket_add_client(sock, client);

    pollfds_layout_free(pfdsl);
    return pollfds_layout_create(devices, sock);
}

void
handle_poll_events(struct pollfds_layout * pfdsl,
                   struct devices * devices,
                   struct socket * sock)
{
    size_t i;
    struct pollfd * pfd;

    if(pfdsl->pfds[POLLFD_INDEX_SOCK].revents > 0) {
        pfdsl = handle_new_connection(pfdsl, devices, sock);
    }

    if(pfdsl->pfds[POLLFD_INDEX_MONITOR].revents > 0) {
        // TODO: implement new device connected

    }

    for(i = pfdsl->devices_start; i <= pfdsl->devices_end; ++i) {
        pfd = &pfdsl->pfds[i];
        if(pfd->revents == POLLHUP) {
            printf("DISCONNECTED\n");
        }
        else if(pfd->revents > 0) {
            handle_key_event(pfd, devices);
        }
    }

    for(i = pfdsl->clients_start; i <= pfdsl->clients_end; ++i) {

    }

}

void
start_polling(struct devices * devices, struct socket * sock)
{
    struct pollfds_layout * pfdsl;
    int rc;

    pfdsl = pollfds_layout_create(devices, sock);

    while(running) {
        rc = poll(pfdsl->pfds, pfdsl->count, -1);

        if(rc < 0) break; // error
        if(rc == 0) continue; // timeout

        handle_poll_events(pfdsl, devices, sock);
    }

    pollfds_layout_free(pfdsl);
}

void
handle_signal_shutdown(int sig)
{
    running = 0;
}

int
setup_signals()
{
    int rc;
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = handle_signal_shutdown;
    rc = sigemptyset(&action.sa_mask);
    if(rc < 0) return rc;
    rc = sigaction(SIGINT, &action, 0);
    if(rc < 0) return rc;

    rc = sigemptyset(&action.sa_mask);
    if(rc < 0) return rc;
    rc = sigaction(SIGTERM, &action, 0);
    if(rc < 0) return rc;

    return rc;
}

int
main(int argi, char** argv)
{
    int rc;
    struct devices devices;
    struct socket * sock;

    rc = setup_signals();
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
