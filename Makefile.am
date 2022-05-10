bin_PROGRAMS=keybindingsd keybindings
noinst_LIBRARIES=libkeybindings.a

libkeybindings_a_SOURCES=\
	src/ipc_sock.c \
	src/logging.c


keybindingsd_CFLAGS=$(LIBEVDEV_CFLAGS) $(LIBUDEV_CFLAGS)
keybindingsd_LDADD=libkeybindings.a $(LIBEVDEV_LIBS) $(LIBUDEV_LIBS)
keybindingsd_SOURCES=src/keybindingsd.c

keybindings_LDADD=libkeybindings.a
keybindings_SOURCES=src/keybindings.c
