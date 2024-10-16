/*
 * Copyright 2024 Google LLC

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
/* A syscall tracer that finds where a fuzz target is being built.

Usage:
```
$ tracer <fuzz_target_source_name> <output_path> <build command>
```

Output (written to <output_path>): 
```
#!/bin/sh
export ENV=val
export ENV=val

cd /path/to/cwd
clang -o fuzz_target ...
```
*/

/* C standard library */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

/* POSIX */
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* Linux */
#include <sys/ptrace.h>
#include <syscall.h>
#include <fcntl.h>

#include <format>
#include <map>
#include <string>
#include <vector>

#include "inspect_utils.h"

#define DEBUG_LOGS 0

#if DEBUG_LOGS
#define debug_log(...)            \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fflush(stdout);               \
    fputc('\n', stderr);          \
  } while (0)
#else
#define debug_log(...)
#endif

#define fatal_log(...)            \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fputc('\n', stderr);          \
    exit(EXIT_FAILURE);           \
  } while (0)

// The PID of the root process we're fuzzing.
pid_t g_root_pid;

// Map of a PID/TID its PID/TID creator and wether it ran exec.
std::map<pid_t, ThreadParent> root_pids;

const int kMaxStringLength = 512;

struct Tracee {
  pid_t pid;
  bool syscall_enter = true;

  Tracee(pid_t pid) : pid(pid) {}
};

pid_t run_child(char **argv) {
  // Run the program under test with its args as a child process
  pid_t pid = fork();
  switch (pid) {
    case -1:
      fatal_log("Fork failed: %s", strerror(errno));
    case 0:
      raise(SIGSTOP);
      execvp(argv[0], argv);
      fatal_log("execvp: %s", strerror(errno));
  }
  return pid;
}

bool contains_fuzz_target_ref(const std::vector<std::string>& args, std::string target_name) {
  for (const auto& arg : args) {
    if (arg.find(target_name) != std::string::npos) {
      return true;
    }
  }
  return false;
}

int trace(std::map<pid_t, Tracee> pids, std::string fuzz_target_name, std::string output_path) {
  unsigned long exit_status = 0;
  while (!pids.empty()) {
    std::vector<pid_t> new_pids;

    auto it = pids.begin();

    while (it != pids.end()) {
      auto pid = it->first;
      auto &tracee = it->second;
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

      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        debug_log("%d exited", pid);
        it = pids.erase(it);
        // Remove pid from the watchlist when it exits
        root_pids.erase(pid);
        continue;
      }

      // ptrace sets 0x80 for syscalls (with PTRACE_O_TRACESYSGOOD set).
      bool is_syscall =
          WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80);
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

      if ((status >> 8 == (SIGTRAP | (PTRACE_EVENT_EXIT << 8)))) {
        debug_log("%d exiting", pid);
        if (pid == g_root_pid) {
          if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &exit_status) == -1) {
            debug_log("ptrace(PTRACE_GETEVENTMSG, %d): %s", pid, strerror(errno));
          }
          debug_log("got exit status from root process: %lu", exit_status);
        }

        if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
          debug_log("ptrace(PTRACE_DETACH, %d): %s", pid, strerror(errno));
        }
        continue;
      }

      if (WIFSTOPPED(status) &&
          (status >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8)) ||
           status >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) ||
           status >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)))) {
        long new_pid;
        if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) == -1) {
          debug_log("ptrace(PTRACE_GETEVENTMSG, %d): %s", pid, strerror(errno));
          continue;
        }
        debug_log("forked %ld", new_pid);
        new_pids.push_back(new_pid);
        root_pids.emplace(new_pid, ThreadParent(pid));
      }

      if (is_syscall) {
        user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
          debug_log("ptrace(PTRACE_GETREGS, %d): %s", pid, strerror(errno));
          continue;
        }

        if (tracee.syscall_enter) {
          if (regs.orig_rax == __NR_execve) {
            // This is a new process.
            auto parent = root_pids[pid];
            parent.ran_exec = true;
            root_pids[pid] = parent;

            auto pathname = read_string(pid, regs.rdi, kMaxStringLength);
            auto argv = read_null_pointer_terminated_array(pid, regs.rsi, kMaxStringLength, 128);
            auto envp = read_null_pointer_terminated_array(pid, regs.rdx, kMaxStringLength, 128);

            if (contains_fuzz_target_ref(argv, fuzz_target_name)) {
              // We found the fuzz target build command!
              FILE* fp = fopen(output_path.c_str(), "w");
              fprintf(fp, "#!/bin/sh\n");
              for (auto& env : envp) {
                auto pos = env.find("=");
                // TODO: Properly shell escape this.
                env = env.insert(pos + 1, "'");
                env += "'";
                fprintf(fp, "export %s\n", env.c_str());
              }

              std::string cwd_path = std::format("/proc/{}/cwd", pid);
              char real_cwd[kMaxStringLength] = {0};
              readlink(cwd_path.c_str(), real_cwd, kMaxStringLength - 1);

              fprintf(fp, "cd %s\n", real_cwd);
              for (const auto& arg : argv) {
                fprintf(fp, "%s ", arg.c_str());
              }
              fprintf(fp, "\n");
              fclose(fp);
              chmod(output_path.c_str(), 0755);
            }
          }
        }

        tracee.syscall_enter = !tracee.syscall_enter;
      }

      if (ptrace(PTRACE_SYSCALL, pid, nullptr, sig) == -1) {
        debug_log("ptrace(PTRACE_SYSCALL, %d): %s", pid, strerror(errno));
        continue;
      }

      ++it;
    }

    for (const auto &pid : new_pids) {
      pids.emplace(pid, Tracee(pid));
    }
  }
  return static_cast<int>(exit_status >> 8);
}

int main(int argc, char **argv) {
  if (argc <= 3) {
    fatal_log("Expecting at least three arguments, received %d", argc - 1);
  }

  std::string fuzz_target_name = argv[1];
  std::string output_path = argv[2];
  pid_t pid = run_child(argv + 3);

  long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                 PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                 PTRACE_O_TRACEEXIT;

  if (ptrace(PTRACE_SEIZE, pid, nullptr, options) == -1) {
    fatal_log("ptrace(PTRACE_SEIZE): %s", strerror(errno));
  }

  if (waitpid(pid, nullptr, __WALL) == -1) {
    fatal_log("waitpid: %s", strerror(errno));
  }

  if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
    fatal_log("ptrace(PTRACE_SYSCALL): %s", strerror(errno));
  }

  g_root_pid = pid;
  std::map<pid_t, Tracee> pids;
  pids.emplace(pid, Tracee(pid));
  root_pids.emplace(pid, ThreadParent(pid));
  return trace(pids, fuzz_target_name, output_path);
}
