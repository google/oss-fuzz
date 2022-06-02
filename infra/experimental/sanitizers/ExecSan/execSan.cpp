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
#include <map>
#include <vector>
#include <set>
#include <sstream>

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

// The magic string that we'll use to detect full control over the command
// executed.
const std::string kTripWire = "/tmp/tripwire";
// The PID of the root process we're fuzzing.
pid_t g_root_pid;
// Assuming the longest pathname is "/bin/bash".
const int kShellPathnameLength = 10;
// Assuming the syntax error pattern is
//   within the first 100 chars of the write buffer.
const int kErrorMessageLength = 100;
// Shell injection bug confirmed with /tmp/tripwire.
const int kShellInjection = 1;
// Shell corruption bug speculated based on syntax error.
const int kShellCorruption = 2;
// Shells used by Processes.
std::map<pid_t, std::string> pidShellMap;

// Two kinds of bugs to detect.
std::map<int, std::string> kBugMessageMap = {
  {kShellInjection,  "Shell injection"},
  {kShellCorruption, "Shell corruption"},
};

// Shells to inspect.
std::set <std::string> kShellSet = {
  "sh",
  "bash",
  "csh",
  "dash",
  "zsh"
};

// Syntax error messages of each shell.
std::map<std::string, std::set<std::string>> kShellSytaxErrorMap = {
  {
    "sh",
    {
      " command not found",  // General
      " syntax error",       // Unfinished " or ' or ` or if, leading | or ;
      " event not found",    // ! leads large numbers
      " no such file",       // Leading < or /
    }
  },
  {
    "bash",
    {
      " command not found",  // General
      " syntax error",       // Unfinished " or ' or ` or if, leading | or ;
      " event not found",    // ! leads large numbers
      " no such file",       // Leading < or /
    }
  },
  {
    "csh",
    {
      " command not found",    // General
      " unmatched",            // Unfinished " or ' or `, leading ;
      " missing",              // Unfinished {
      "invalid null command",  // Leading | or < or >
      " no match",             // Leading ? or [ or *
      "modifier failed",       // Leading ^
      " no such job",          // Leading %
      " undefined variable",   // Containing $
      " event not found",      // ! leads large numbers
    }
  },
  {
    "dash",
    {
      " not found",     // General
      " syntax error",  // Unfinished " or ' or ` or if, leading | or ;
      " no such file",  // Leading <
    }
  },
  {
    "zsh",
    {
      " command not found",               // General
      " syntax error",                    // Unfinished " or ' or `
      " no such file or directory",       // Leading < or /
      " parse error",                     // Leading |
      " no such user or named directory", // Leading ~
    }
  },
};

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
      execv(argv[0], argv);
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

// Construct a string with the memory specified in a register.
std::string read_register_string(pid_t pid, unsigned long reg, unsigned long length) {
  auto memory = read_memory(pid, reg, length);
  if (!memory.size()) {
    return "";
  }

  std::string content(reinterpret_cast<char*>(
        memory.data()), std::min(memory.size(), length));
  return content;
}

void report_bug(int bug_code) {
  // Report the bug found based on the bug code.
  fprintf(stderr, "===BUG DETECTED: %s===\n", kBugMessageMap[bug_code].c_str());
  // Rely on sanitizers/libFuzzer to produce a stacktrace by sending SIGABRT
  // to the root process.
  // Note: this may not be reliable or consistent if shell injection happens
  // in an async way.
  kill(g_root_pid, SIGABRT);
  _exit(0);
}

void inspect_for_injection(pid_t pid, const user_regs_struct &regs) {
  // Inspect a PID's registers for the sign of shell injection.
  std::string path = read_register_string(pid, regs.rdi, kTripWire.length());
  if (!path.length()) {
    return;
  }
  debug_log("inspecting");
  if (path == kTripWire) {
    report_bug(kShellInjection);
  }
}

std::string get_pathname(pid_t pid, const user_regs_struct &regs) {
  // Parse the pathname from the memory specified in the ROI register.
  std::string raw_content = read_register_string(pid, regs.rdi, kShellPathnameLength);

  std::string pathname = raw_content.substr(0, raw_content.find(" "));
  debug_log("Pathname is %s (len %lu)\n", pathname.c_str(), pathname.length());
  return pathname;
  }

std::string match_shell(std::string shell_pathname) {
  // Identify the name of the shell used in the pathname.
  for (std::string known_shell : kShellSet) {
    if (shell_pathname.length() < known_shell.length()) {
      continue;
    }
    std::string shell = shell_pathname.substr(shell_pathname.find_last_of("/")+1, known_shell.length());
    if (!shell.compare(known_shell)) {
      debug_log("Matched %s\n", shell.c_str());
      return shell;
    }
  }
  return "";
}

std::string get_shell(pid_t pid, const user_regs_struct &regs) {
  // Get shell name used in a PID.
  std::string shell_pathname = get_pathname(pid, regs);
  if (shell_pathname.length()) {
    return match_shell(shell_pathname);
  } else {
    return "";
  }
}

void match_error_pattern(std::string buffer, std::string shell) {
  // Identify the error pattern in the write buffer and report a bug if matched.
  std::istringstream ss{buffer};
  std::string token;
  while (std::getline(ss, token, ':')) {
    if (token.empty()) {
      continue;
    }
    auto error_patterns = kShellSytaxErrorMap[shell];
    for(auto it = error_patterns.begin(); it != error_patterns.end(); ++it) {
      if(!strncasecmp(token.c_str(),it->c_str(), std::min(token.length(), it->length()))) {
        buffer = buffer.substr(0, buffer.find("\n"));
        printf("--- Found a sign of shell corruption ---\n"
               "%s\n"
               "----------------------------------------\n", buffer.c_str());
        report_bug(kShellCorruption);
      }
    }
  }
}

void inspect_for_corruption(pid_t pid, const user_regs_struct &regs) {
  // Inspect a PID's registers for shell corruption.
  std::string buffer = read_register_string(pid, regs.rsi, kErrorMessageLength);
  debug_log("Write buffer: %s\n", buffer.c_str());
  match_error_pattern(buffer, pidShellMap[pid]);
}

void trace(std::map<pid_t, Tracee> pids) {
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
        it = pids.erase(it);
        // Remove pid from the watchlist when it exits
        pidShellMap.erase(pid);
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
        user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
          debug_log("ptrace(PTRACE_GETREGS, %d): %s", pid, strerror(errno));
          continue;
        }

        if (tracee.syscall_enter) {
          if (regs.orig_rax == __NR_execve) {
            inspect_for_injection(pid, regs);
            std::string shell = get_shell(pid, regs);
            debug_log("Shell parsed: %s", shell.c_str());
            if (shell.compare("")) {
              pidShellMap.insert(std::make_pair(pid, shell));
            }
          }

          if (regs.orig_rax == __NR_write && pidShellMap.find(pid) != pidShellMap.end()) {
            debug_log("Inspect the buffer of write after execve.");
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

  pid_t pid = run_child(argv + 1);

  long options = 
    PTRACE_O_TRACESYSGOOD
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

  g_root_pid = pid;
  std::map<pid_t, Tracee> pids;
  pids.emplace(pid, Tracee(pid));
  trace(pids);
}
