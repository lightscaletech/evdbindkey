#ifndef _KEYBINDINGS_SIGNAL_H_
#define _KEYBINDINGS_SIGNAL_H_

#include <signal.h>

extern sig_atomic_t signal_running;

int signal_setup_actions();

#endif
