/*
 * tmux-stubs.c - Stub/fallback definitions for tmux globals and functions
 *
 * These symbols are defined in tmux.c which has main(), so we provide
 * versions for fuzzing builds. Use TMUX_USE_REAL_SOURCE to link against
 * a modified tmux.o with renamed main().
 *
 * When not using real source, weak symbols allow real implementations
 * from other tmux files to override these where available.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "tmux.h"

#ifdef TMUX_USE_REAL_SOURCE
/*
 * When using real source, only provide the global variable definitions.
 * The actual tmux.c (compiled with -Dmain=tmux_main_unused) provides
 * all function implementations.
 */

/* These are defined in the real tmux.o when TMUX_USE_REAL_SOURCE is set */

#else /* !TMUX_USE_REAL_SOURCE */

/* Global variables - always needed since tmux.o is excluded */
struct options     *global_options;
struct options     *global_s_options;
struct options     *global_w_options;
struct environ     *global_environ;
const char         *socket_path;
struct timeval      start_time;
int                 ptm_fd = -1;
const char         *shell_command;

/*
 * Weak attribute allows these to be overridden by real implementations
 * if they exist elsewhere in the tmux codebase.
 */
#define WEAK __attribute__((weak))

/* Version - use real if available */
WEAK const char *
getversion(void)
{
    return "3.4-fuzz";
}

/* Timer - real implementation */
WEAK uint64_t
get_timer(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Intentional no-op for fuzzing - don't modify file descriptors */
WEAK void
setblocking(int fd, int state)
{
    (void)fd;
    (void)state;
}

/* Intentional stub for fuzzing - avoid filesystem access */
WEAK const char *
find_home(void)
{
    return "/tmp";
}

/* Intentional stub for fuzzing - avoid filesystem access */
WEAK const char *
find_cwd(void)
{
    return "/tmp";
}

/* Simplified for fuzzing - real version checks filesystem */
WEAK int
checkshell(const char *shell)
{
    if (shell == NULL || *shell == '\0')
        return 0;
    return 1;
}

/* Signal name lookup - stub version */
WEAK const char *
sig2name(int sig)
{
    (void)sig;
    return "UNKNOWN";
}

/* Shell argv0 extraction - real implementation */
WEAK char *
shell_argv0(const char *shell, int is_login)
{
    char *argv0;
    const char *slash;
    
    (void)is_login;
    slash = strrchr(shell, '/');
    if (slash != NULL)
        shell = slash + 1;
    argv0 = xstrdup(shell);
    return argv0;
}

#endif /* TMUX_USE_REAL_SOURCE */
