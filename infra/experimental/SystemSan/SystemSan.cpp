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

#include <algorithm>
#include <filesystem>
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

std::string kEvilLinkBombfile = "/tmp/evil-link-bombfile";
std::string kEvilLinkBombfileContents = "initial";
const std:: string kEvilLinkError = "Symbolic link followed";
const size_t kPathMax = 4096;

// Syntax error messages of each shell.
const std::map<std::string, std::set<std::string>> kShellSyntaxErrors = {
    {"bash",
     {
         ": command not found",  // General
         ": syntax error",       // Unfinished " or ' or ` or if, leading | or ;
         ": missing `]'",        // Unfinished [
         ": event not found",    // ! leads large numbers
         ": No such file or directory",  // Leading < or /
     }},
    {"csh",
     {
         ": Command not found.",         // General
         ": Missing }.",                 // Unfinished {
         "Too many ('s.",                // Unfinished (
         "Invalid null command.",        // Leading | or < or >
         "Missing name for redirect.",   // Single < or >
         ": No match.",                  // Leading ? or [ or *
         "Modifier failed.",             // Leading ^
         "No previous left hand side.",  // A ^
         ": No such job.",               // Leading %
         ": No current job.",            // A %
         ": Undefined variable.",        // Containing $
         ": Event not found.",           // ! leads large numbers
         // TODO: Make this more specific.
         "Unmatched",  // Unfinished " or ' or `, leading ;
     }},
    {"dash",
     {
         "not found",     // General
         "Syntax error",  // Unfinished " or ' or ` or if, leading | or ; or &
         "missing ]",     // Unfinished [
         "No such file",  // Leading <
     }},
    {"zsh",
     {
         ": command not found",                // General
         ": syntax error",                     // Unfinished " or ' or `
         ": ']' expected",                     // Unfinished [
         ": no such file or directory",        // Leading < or /
         ": parse error near",                 // Leading |, or &
         ": no such user or named directory",  // Leading ~
     }},
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

  auto location = std::find(memory.begin(), memory.end(), static_cast<std::byte>(NULL));
  size_t str_length = location - memory.begin();
  std::string content(reinterpret_cast<char *>(memory.data()),
                      std::min(str_length, length));
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

// Identify the exact shell behind sh
std::string identify_sh(std::string path) {
  char shell_pathname[kShellPathnameLength];
  auto written = readlink(path.c_str(), shell_pathname, kShellPathnameLength - 1);
  if (written == -1) {
    std::cerr << "Cannot query which shell is behind sh: readlink failed on "
              << path << ": "
              << strerror(errno) << "\n";
    std::cerr << "Assuming the shell is dash\n";
    return "dash";
  }
  shell_pathname[written] = '\0';

  debug_log("sh links to %s\n", shell_pathname);
  std::string shell_pathname_str(shell_pathname);

  return match_shell(shell_pathname_str);
}

std::string match_shell(std::string binary_pathname) {
  // Identify the name of the shell used in the pathname.
  if (!binary_pathname.length()) {
    return "";
  }

  // We use c_str() to accept only the null terminated string.
  std::string binary_name = binary_pathname.substr(
      binary_pathname.find_last_of("/") + 1).c_str();

  debug_log("Binary is %s (%lu)\n", binary_name.c_str(),
            binary_name.length());

  for (const auto &item : kShellSyntaxErrors) {
    std::string known_shell = item.first;
    if (binary_name == "sh") {
      debug_log("Matched sh: Needs to identify which specific shell it is.\n");
      return identify_sh(binary_pathname);
    }
    if (binary_name == known_shell) {
      debug_log("Matched %s\n", binary_name.c_str());
      return known_shell;
    }
  }
  return "";
}

std::string get_shell(pid_t pid, const user_regs_struct &regs) {
  // Get shell name used in a process.
  std::string binary_pathname = get_pathname(pid, regs);
  return match_shell(binary_pathname);
}

void match_error_pattern(std::string buffer, std::string shell, pid_t pid) {
  auto error_patterns = kShellSyntaxErrors.at(shell);
  for (const auto &pattern : error_patterns) {
    if (buffer.find(pattern) != std::string::npos) {
      std::cerr << "--- Found a sign of shell corruption ---\n"
                << buffer.c_str()
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
  match_error_pattern(buffer, g_shell_pids[pid], pid);
}

void log_file_open(std::string path, int flags, pid_t pid) {
  report_bug(kArbitraryFileOpenError, pid);
  std::cerr << "===File opened: " << path.c_str() << ", flags = " << flags << ",";
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

std::string read_evil_link_bombfile() {
    const std::ifstream bombfile(kEvilLinkBombfile,
                                 std::ios_base::binary);
    if (bombfile.fail())
      return "";
    std::stringstream stream;
    stream << bombfile.rdbuf();
    return stream.str();
}

// https://oss-fuzz.com/testcase-detail/4882113260552192
void report_bug_in_process(std::string bug_type, pid_t pid) {
  std::cerr << "===BUG DETECTED: " << bug_type << "===" << std::endl;
  tgkill(root_pids[pid].parent_tid, pid, SIGABRT);
}

void inspect_for_evil_link(pid_t pid, const user_regs_struct &regs) {
  (void) regs;
  std::string contents = read_evil_link_bombfile();
  if ((contents.compare(kEvilLinkBombfileContents)) != 0) {

    report_bug_in_process(kEvilLinkError, pid);
  }
}

void evil_openat_hook(pid_t pid, const user_regs_struct &regs) {
  std::string path = read_string(pid, regs.rsi, kPathMax);
  if (!path.length()) {
    return;
  }
  if (std::filesystem::exists(path))
    return;
  size_t slash_idx = path.rfind('/');
  if (slash_idx == std::string::npos)
    return;

  std::string dir = path.substr(0, slash_idx);
  if ((dir.compare("/tmp")) != 0)
    return;

  std::string command = "rm -f " + path + " && ln -s " + kEvilLinkBombfile + " " + path;
  std::cout << "COMMAND " << command << std::endl;
  system(command.c_str());
}

void initialize_evil_link_bombfile() {
  std::string command = ("printf " + kEvilLinkBombfileContents + " > " +
                         kEvilLinkBombfile);
  std::cout << "COMMAND " << command << std::endl;
  system(command.c_str());
  system(("cat " + kEvilLinkBombfile).c_str());
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

      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        debug_log("%d exited", pid);
        it = pids.erase(it);
        // Remove pid from the watchlist when it exits
        g_shell_pids.erase(pid);
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
            inspect_for_injection(pid, regs);
            std::string shell = get_shell(pid, regs);
            if (shell != "") {
              debug_log("Shell parsed: %s", shell.c_str());
              g_shell_pids.insert(std::make_pair(pid, shell));
            }
          }

          inspect_dns_syscalls(pid, regs);

          if (regs.orig_rax == __NR_openat) {
            // TODO(metzman): Re-enable this once we have config/flag support.
            // inspect_for_arbitrary_file_open(pid, regs);
            evil_openat_hook(pid, regs);
          }

          if (regs.orig_rax == __NR_close) {
            // TODO(metzman): Re-enable this once we have config/flag support.
            // inspect_for_arbitrary_file_open(pid, regs);
            inspect_for_evil_link(pid, regs);
          }

          if (regs.orig_rax == __NR_write &&
              g_shell_pids.find(pid) != g_shell_pids.end()) {
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


  initialize_evil_link_bombfile();

  // Create an executable tripwire file, as programs may check for existence
  // before actually calling exec.
  std::ofstream tripwire(kTripWire);
  tripwire.close();
  chmod(kTripWire.c_str(), 0755);

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
