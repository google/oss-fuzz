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
/* A detector that uses ptrace to identify DNS arbitrary resolutions. */

/* C standard library */
#include <signal.h>

/* POSIX */
#include <unistd.h>
#include <limits.h>

/* Linux */
#include <sys/ptrace.h>

#include <iostream>
#include <string>
#include <vector>
#include <map>

#include "inspect_utils.h"

extern pid_t g_root_pid;
extern std::map<pid_t, ThreadParent> root_pids;

std::vector<std::byte> read_memory(pid_t pid, unsigned long long address,
                                   size_t size) {
  std::vector<std::byte> memory;

  for (size_t i = 0; i < size; i += sizeof(long)) {
    long word = ptrace(PTRACE_PEEKTEXT, pid, address + i, 0);
    if (word == -1) {
      return memory;
    }

    std::byte *word_bytes = reinterpret_cast<std::byte *>(&word);
    memory.insert(memory.end(), word_bytes, word_bytes + sizeof(long));
  }

  return memory;
}

std::string read_null_terminated(pid_t pid, unsigned long long address) {
  std::string str;
  while (1) {
    long word = ptrace(PTRACE_PEEKDATA, pid, address, 0);
    if (word == -1) {
      return str;
    }
    address += sizeof(long);
    const char *word_bytes = reinterpret_cast<const char*>(&word);
    for (size_t i = 0; i < sizeof(long); i++) {
      if (word_bytes[i] == 0) {
        debug_log("read_null_terminated() read %s (%lu bytes)", str.c_str(), str.length());
        return str;
      }
      str.push_back(word_bytes[i]);
    }
  }
}

std::vector<std::string> read_argv(pid_t pid, unsigned long long address) {
  std::vector<std::string> argv;
  for (size_t i = 0; _POSIX_ARG_MAX; i++) {
    long p = ptrace(PTRACE_PEEKDATA, pid, address, 0);
    debug_log("argv[%lu] @ 0x%llx = 0x%lx", i, address, p);
    if (p == -1) {
      break;
    }
    address += sizeof(long);
    std::string arg = read_null_terminated(pid, p);
    argv.push_back(arg);
    if (p == 0) {
      break;
    }
  }
  return argv;
}

void report_bug(std::string bug_type, pid_t tid) {
  // Report the bug found based on the bug code.
  std::cerr << "===BUG DETECTED: " << bug_type.c_str() << "===\n";
  // Rely on sanitizers/libFuzzer to produce a stacktrace by sending SIGABRT
  // to the root process.
  // Note: this may not be reliable or consistent if shell injection happens
  // in an async way.
  // Find the thread group id, that is the pid.
  pid_t pid = tid;
  auto parent = root_pids[tid];
  while (!parent.ran_exec) {
    // Find the first parent which ran exec syscall.
    if (parent.parent_tid == g_root_pid) {
      break;
    }
    pid = parent.parent_tid;
    parent = root_pids[parent.parent_tid];
  }
  tgkill(pid, tid, SIGABRT);
}
