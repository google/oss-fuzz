/*
 * Copyright 2022 Google LLC

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *      http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* A detector that uses ptrace to identify shell injection vulnerabilities. */

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

/* POSIX */
#include <unistd.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

#include <fstream>
#include <string>
#include <vector>
#include <set>

const std::string kTripWire = "/tmp/tripwire";

#define DEBUG_LOGS 0

#if DEBUG_LOGS
#define debug_log(...) \
  do { \
    fprintf(stderr, __VA_ARGS__); fflush(stdout); \
    fputc('\n', stderr); \
  } while (0)
#else
#define debug_log(...)
#endif

#define fatal_log(...) \
  do { \
    fprintf(stderr, __VA_ARGS__); \
    fputc('\n', stderr); \
    exit(EXIT_FAILURE); \
  } while (0)

pid_t run_child(char **argv) {
  // Run the program under test with its args as a child process
  pid_t pid = fork();
  switch (pid) {
    case -1:
      fatal_log("Fork failed: %s", strerror(errno));
    case 0:
      raise(SIGSTOP);
      execv(argv[1], argv + 1);
      fatal_log("execv: %s", strerror(errno));
  }
  return pid;
}

std::vector<std::byte> read_memory(pid_t pid, unsigned long long address, size_t size) {
  std::vector<std::byte> memory;

  for (size_t i = 0; i < size; i += sizeof(long)) {
    long word = ptrace(PTRACE_PEEKTEXT, pid, address + i, 0);
    if (word == -1) {
      return memory;
    }

    std::byte *word_bytes = reinterpret_cast<std::byte*>(&word);
    memory.insert(memory.end(), word_bytes, word_bytes+sizeof(long));
  }

  return memory;
}

void inspect(pid_t pid, const user_regs_struct &regs) {
  auto memory = read_memory(pid, regs.rdi, kTripWire.length());
  if (memory.size() == 0) {
    return;
  }

  std::string path(reinterpret_cast<char*>(
        memory.data()), std::min(memory.size(), kTripWire.length()));
  debug_log("inspecting");
  if (path == kTripWire) {
    kill(pid, SIGKILL);
    fprintf(stderr, "===BUG DETECTED: Shell injection===\n");
    // TODO: Get/print stacktrace.
    _exit(1);
  }
}

void trace(std::set<pid_t> pids) {
  while (!pids.empty()) {
    std::vector<pid_t> new_pids;

    auto it = pids.begin();
    while (it != pids.end()) {
      auto pid = *it;
      int status = 0;

      int result = waitpid(pid, &status, __WALL | WNOHANG);
      if (result == -1) {
        it = pids.erase(it);
        continue;
      }

      if (result == 0) {
        // Nothing to report yet.
        ++it;
        continue;
      }

      debug_log("finished waiting %d", pid);

      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        debug_log("%d exited", pid); 
        it = pids.erase(it);
        continue;
      }

      // ptrace sets 0x80 for syscalls (with PTRACE_O_TRACESYSGOOD set).
      bool is_syscall = WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80);
      int sig = 0;
      if (!is_syscall) {
        // Handle generic signal.
        siginfo_t siginfo;
        if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &siginfo) == -1) {
          debug_log("ptrace(PTRACE_GETSIGINFO, %d): %s", pid, strerror(errno));
          continue;
        }
        sig = siginfo.si_signo;
        debug_log("forwarding signal %d to %d", sig, pid);
      }

      if (WIFSTOPPED(status) && 
          (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) ||
           status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)) ||
           status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)))) {
        long new_pid;
        if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) == -1) {
          debug_log("ptrace(PTRACE_GETEVENTMSG, %d): %s", pid, strerror(errno));
          continue;
        }
        debug_log("forked %ld", new_pid);
        new_pids.push_back(new_pid);
      }

      if (is_syscall) {
        // TODO: distinguish between syscall enter and exit.
        user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
          debug_log("ptrace(PTRACE_GETREGS, %d): %s", pid, strerror(errno));
          continue;
        }

        if (regs.orig_rax == __NR_execve) {
          inspect(pid, regs);
        }
        // TODO: Check for commands with invalid syntax passed to /bin/sh and
        // other shells.
        // TODO: It's possible the process we're fuzzing can communicate with
        // another process to execute code. Our check wouldn't catch this
        // currently.
      }

      debug_log("tracing %d %d", pid, sig);
      if (ptrace(PTRACE_SYSCALL, pid, nullptr, sig) == -1) {
        debug_log("ptrace(PTRACE_SYSCALL, %d): %s", pid, strerror(errno));
        continue;
      }

      ++it;
    }

    pids.insert(new_pids.begin(), new_pids.end());
  }
}

int main(int argc, char **argv) {
  if (argc <= 1) {
    fatal_log("Expecting at least one arguments, received %d", argc - 1);
  }

  // Create an executable tripwire file, as programs may check for existence
  // before actually calling exec.
  std::ofstream tripwire(kTripWire);
  tripwire.close();
  chmod(kTripWire.c_str(), 0755);

  pid_t pid = run_child(argv);

  long options = 
    PTRACE_O_EXITKILL
    | PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE;

  if (ptrace(PTRACE_SEIZE, pid, nullptr, options) == -1) {
    fatal_log("ptrace(PTRACE_SEIZE): %s", strerror(errno));
  }

  if (waitpid(pid, nullptr, __WALL) == -1) {
    fatal_log("waitpid: %s", strerror(errno));
  }

  if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
    fatal_log("ptrace(PTRACE_SYSCALL): %s", strerror(errno));
  }

  std::set<pid_t> pids;
  pids.insert(pid);
  trace(pids);
}
