#include "signal.h"

#include <string.h>
#include <signal.h>

sig_atomic_t signal_running;

static void
handle_signal_shutdown(int sig)
{
    signal_running = 0;
}

int
signal_setup_actions()
{
    int rc;
    struct sigaction action;

    signal_running = 1;

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
