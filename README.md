# evdbindkey
A simple tool to keystrokes to commands using libevdev.

## Dependencies
- autotools
- c compiler (gcc)
- libevdev
- libudev

## Build

Generate the build system files:

``` shell
automake --add-missing
autoreconf
```

Then build with:

``` shell
./configure
make
```

## Install

``` shell
make install
```

## Configuration
The configuration is done via a user config file. You need to create a file in
`~/.config/evdbindkey`

It uses the following structure.

```
# config file

# Volume key commands
KEY_VOLUMEDOWN
    /home/user/scripts/voldown.sh

KEY_VOLUMEUP
    /home/user/scripts/volup.sh

KEY_MUTE
    /home/user/scripts/volmute.sh

# Multiple keys
KEY_LEFTCTRL + KEY_LEFTALT + KEY_LEFTSHIFT + KEY_D
    /home/user/scripts/dock.sh
```

To find a list of all key code options look in
`/usr/include/linux/input-event-codes.h`

## Running
This is split into two parts the priviledges server application `evdbindkeyd`
and the user client program `evbindkey`.

Run `evbindkeyd` first, this should be run as root. Then run `evbindkey` as your
users.
