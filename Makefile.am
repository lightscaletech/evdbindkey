bin_PROGRAMS=evdbindkeyd evdbindkey

evdbindkeyd_CFLAGS=$(LIBEVDEV_CFLAGS) $(LIBUDEV_CFLAGS)
evdbindkeyd_LDADD=$(LIBEVDEV_LIBS) $(LIBUDEV_LIBS)
evdbindkeyd_SOURCES=src/evdbindkeyd.c \
	src/ipc_sock.c \
	src/signal.c \
	src/logging.c

evdbindkey_CFLAGS=$(LIBEVDEV_CFLAGS)
evdbindkey_LDADD=$(LIBEVDEV_LIBS)
evdbindkey_SOURCES=src/evdbindkey.c \
	src/client_config.c \
	src/ipc_sock.c \
	src/signal.c \
	src/logging.c
