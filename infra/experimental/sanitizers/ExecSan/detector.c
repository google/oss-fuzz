#define _POSIX_C_SOURCE 200112L

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* POSIX */
#include <unistd.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/reg.h>
#include <sys/ptrace.h>

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

pid_t run_child(char **argv) {
  // Run the program under test with its args as a child process
  pid_t pid = fork();
  switch (pid) {
    case -1: /* error */
      FATAL("Fork failed: %s", strerror(errno));
    case 0:  /* child */
      ptrace(PTRACE_TRACEME, 0, 0, 0);
      /* Because we're now a tracee, execvp will block until the parent
       * attaches and allows us to continue. */
      execv(argv[1], argv + 1);
      FATAL("%s", strerror(errno));
  }
  return pid;
}

void sync_syscall(pid_t pid) {
  // Run and pause the child process before/after of the next system call
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
    FATAL("%s", strerror(errno));
  if (waitpid(pid, NULL, WUNTRACED) == -1)
    FATAL("%s", strerror(errno));
}

void inspect(pid_t pid) {
  // Check for bombfile upon exec
  struct stat stat_buf;
  if (!stat("/tmp/bombfile", &stat_buf)) {
    ptrace(PTRACE_KILL, pid, NULL, NULL);
    printf("===BUG DETECTED: Shell injection===\n");
    exit(1);
  }
}

int main(int argc, char **argv) {
  if (argc <= 1)
    FATAL("Expecting at least one arguments, received %d", argc - 1);

  pid_t pid = run_child(argv);
  /* Gather system call arguments */
  struct user_regs_struct regs;
  int cloned = 0;

  /* parent */
  // sync with child process
  if (waitpid(pid, NULL, WUNTRACED) == -1)
    FATAL("%s", strerror(errno));
  // Ensures that the tracee will never escape
  long data = PTRACE_O_EXITKILL
//      | PTRACE_O_TRACEFORK
//      | PTRACE_O_TRACEVFORK
//      | PTRACE_O_TRACECLONE
//      | PTRACE_O_TRACEEXEC
      ;
  ptrace(PTRACE_SETOPTIONS, pid, NULL, data);

  while (kill(pid, 0) != -1) {
    /* Enter next system call */
    sync_syscall(pid);

    /* Gather system call arguments */
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
      FATAL("%s", strerror(errno));

    cloned = cloned || regs.orig_rax == __NR_clone;

    /* Run system call and stop on exit */
    sync_syscall(pid);

    ptrace(PTRACE_GETREGS, pid, 0, &regs);

    if (regs.orig_rax == __NR_execve) {
      inspect(pid);
    }
    if (regs.orig_rax == __NR_wait4 && cloned) {
      cloned = 0;
      inspect(pid);
    }
  }
}
