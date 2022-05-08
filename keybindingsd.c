#include <stdio.h>
#include <fcntl.h>
#include <libudev.h>
#include <libevdev/libevdev.h>

int main(int argi, char** argv) {

    struct udev * udev = udev_new();

    struct udev_enumerate * enumerate = udev_enumerate_new(udev);

    struct udev_list_entry * devices = 0;

    udev_enumerate_add_match_is_initialized(enumerate);
    udev_enumerate_add_match_subsystem(enumerate, "input");
    udev_enumerate_add_match_property(enumerate, "ID_INPUT_KEYBOARD", "1");
    udev_enumerate_scan_devices(enumerate);

    devices = udev_enumerate_get_list_entry(enumerate);

    struct udev_list_entry * entry = 0;
    struct udev_device * dev;
    udev_list_entry_foreach(entry, devices) {
        const char * devpath, * nodepath;

        devpath = udev_list_entry_get_name(entry);
        dev = udev_device_new_from_syspath(udev, devpath);
        nodepath = udev_device_get_devnode(dev);

        if(nodepath) {
            printf("%s\n", nodepath);
        }
    }

    udev_enumerate_unref(enumerate);
    udev_unref(udev);

    return 0;
}
