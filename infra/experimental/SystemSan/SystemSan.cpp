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

#include <cstddef>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "inspect_utils.h"
#include "inspect_dns.h"

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

// The magic string that we'll use to detect full control over the command
// executed.
const std::string kTripWire = "/tmp/tripwire";
// Shell injection bug confirmed with /tmp/tripwire.
const std::string kInjectionError = "Shell injection";
// Shell corruption bug detected based on syntax error.
const std::string kCorruptionError = "Shell corruption";
// The magic string that we'll use to detect arbitrary file open
const std::string kFzAbsoluteDirectory = "/fz/";
// Arbitrary file open in /fz/
const std::string kArbitraryFileOpenError = "Arbitrary file open";
// Assuming only shorter (than this constant) top dir are legitly used.
constexpr int kRootDirMaxLength = 16;

// The PID of the root process we're fuzzing.
pid_t g_root_pid;

// Map of a PID/TID its PID/TID creator and wether it ran exec.
std::map<pid_t, ThreadParent> root_pids;

// Assuming the longest pathname is "/bin/bash".
constexpr int kShellPathnameLength = 20;

std::set<std::string> kShellSyntaxErrors = {
  // bash
  ": syntax error",       // Unfinished " or ' or ` or if, leading | or ;
  ": missing `]'",        // Unfinished [
  ": event not found",    // ! leads large numbers
  ": No such file or directory",  // Leading < or /
  ": command not found",     // General. Also matches bash's !!!
  // dash
  ": not found",     // General. Also matches bash's !!!
  // Also matches bash's.
  "syntax error",  // Unfinished " or ' or ` or if, leading | or ; or &.
  "missing ]",     // Unfinished [
  "No such file",  // Leading <
  ": not found",
  ": Syntax error: EOF in backquote substitution",
};

// Shells used by Processes.
std::map<pid_t, std::string> g_shell_pids;

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

// Construct a string with the memory specified in a register.
std::string read_string(pid_t pid, unsigned long reg, unsigned long length) {
  auto memory = read_memory(pid, reg, length);
  if (!memory.size()) {
    return "";
  }

  std::string content(reinterpret_cast<char *>(memory.data()),
                      std::min(memory.size(), length));
  return content;
}

void inspect_for_injection(pid_t pid, const user_regs_struct &regs) {
  // Inspect a PID's registers for the sign of shell injection.
  std::string path = read_string(pid, regs.rdi, kTripWire.length());
  if (!path.length()) {
    return;
  }
  debug_log("inspecting");
  if (path == kTripWire) {
    report_bug(kInjectionError, pid);
  }
}

std::string get_pathname(pid_t pid, const user_regs_struct &regs) {
  // Parse the pathname from the memory specified in the RDI register.
  std::string pathname = read_string(pid, regs.rdi, kShellPathnameLength);
  debug_log("Pathname is %s (len %lu)\n", pathname.c_str(), pathname.length());
  return pathname;
}

std::string match_shell(std::string binary_pathname);


void match_error_pattern(std::string buffer, std::string shell, pid_t pid) {
  for (const auto &pattern : kShellSyntaxErrors) {
    auto position = buffer.find(pattern);

    // Check that we are ending with the syntax error.
    if (position != std::string::npos) {
      std::cerr << "pattern: " << pattern << " buffer: " << buffer << std::endl;
      auto pattern_end = position + pattern.length();
      if (pattern_end != buffer.length() && ((pattern_end != buffer.length() - 1) && buffer.back() != '\n') ) {
        std::cerr << "pattern_end: " << pattern_end << " buffer.length(): " << buffer.length() << std::endl;
        printf("continue\n");
        continue;
      }
      printf("not continue\n");
      std::cerr << "--- Found a sign of shell corruption ---\n"
                << buffer
                << "\n----------------------------------------\n";
      // If a shell corruption error happens, kill its parent.
      auto parent = root_pids[pid];
      while (!parent.ran_exec) {
        if (parent.parent_tid == g_root_pid) {
          break;
        }
        parent = root_pids[parent.parent_tid];
      }
      report_bug(kCorruptionError, parent.parent_tid);
    }
  }
}

void inspect_for_corruption(pid_t pid, const user_regs_struct &regs) {
  // Inspect a PID's registers for shell corruption.
  std::string buffer = read_string(pid, regs.rsi, regs.rdx);
  debug_log("Write buffer: %s\n", buffer.c_str());
  match_error_pattern(buffer, "dash", pid);
}

void log_file_open(std::string path, int flags, pid_t pid) {
  report_bug(kArbitraryFileOpenError, pid);
  std::cerr << "===File opened: " << path << ", flags = " << flags << ",";
  switch (flags & 3) {
    case O_RDONLY:
      std::cerr << "O_RDONLY";
      break;
    case O_WRONLY:
      std::cerr << "O_WRONLY";
      break;
    case O_RDWR:
      std::cerr << "O_RDWR";
      break;
    default:
      std::cerr << "unknown";
  }
  std::cerr << "===\n";
}

bool has_unprintable(const std::string &value) {
  for (size_t i = 0; i < value.length(); i++) {
    if (value[i] & 0x80) {
      return true;
    }
  }
  return false;
}

void inspect_for_arbitrary_file_open(pid_t pid, const user_regs_struct &regs) {
  // Inspect a PID's register for the sign of arbitrary file open.
  std::string path = read_string(pid, regs.rsi, kRootDirMaxLength);
  if (!path.length()) {
    return;
  }
  if (path.substr(0, kFzAbsoluteDirectory.length()) == kFzAbsoluteDirectory) {
    log_file_open(path, regs.rdx, pid);
    return;
  }
  if (path[0] == '/' && path.length() > 1) {
    std::string path_absolute_topdir = path;
    size_t root_dir_end = path.find('/', 1);
    if (root_dir_end != std::string::npos) {
      path_absolute_topdir = path.substr(0, root_dir_end);
    }
    if (has_unprintable(path_absolute_topdir)) {
      struct stat dirstat;
      if (stat(path_absolute_topdir.c_str(), &dirstat) != 0) {
        log_file_open(path, regs.rdx, pid);
      }
    }
  }
}

int trace(std::map<pid_t, Tracee> pids) {
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

      debug_log("finished waiting %d", pid);

      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        debug_log("%d exited", pid);
        // it = pids.erase(it);
        // Remove pid from the watchlist when it exits
        // g_shell_pids.erase(pid);
        // root_pids.erase(pid);
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
            inspect_for_injection(pid, regs);
            std::string shell = "bash";
            if (shell != "") {
              debug_log("Shell parsed: %s", shell.c_str());
              printf("SHELL PID: %ul\n", pid);
              g_shell_pids.insert(std::make_pair(pid, shell));
            }
          }

          inspect_dns_syscalls(pid, regs);

          if (regs.orig_rax == __NR_openat) {
            // TODO(metzman): Re-enable this once we have config/flag support.
            // inspect_for_arbitrary_file_open(pid, regs);
          }

          if (regs.orig_rax == __NR_write//  &&
              // g_shell_pids.find(pid) != g_shell_pids.end()
              ) {
            debug_log("Inspecting the `write` buffer of shell process %d.",
                      pid);
            inspect_for_corruption(pid, regs);
          }
        }

        // TODO: Check for commands with invalid syntax passed to /bin/sh and
        // other shells.
        // TODO: It's possible the process we're fuzzing can communicate with
        // another process to execute code. Our check wouldn't catch this
        // currently.
        tracee.syscall_enter = !tracee.syscall_enter;
      }

      debug_log("tracing %d %d", pid, sig);
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
  if (argc <= 1) {
    fatal_log("Expecting at least one arguments, received %d", argc - 1);
  }

  // Create an executable tripwire file, as programs may check for existence
  // before actually calling exec.
  std::ofstream tripwire(kTripWire);
  tripwire.close();
  chmod(kTripWire.c_str(), 0755);
  setenv("SHELL", "dash", 1);

  pid_t pid = run_child(argv + 1);

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
  return trace(pids);
}
