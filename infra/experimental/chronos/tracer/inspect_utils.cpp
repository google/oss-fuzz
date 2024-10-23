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

// Construct a string with the memory specified in a register.
std::string read_string(pid_t pid, unsigned long long reg, unsigned long length) {
  auto memory = read_memory(pid, reg, length);
  if (!memory.size()) {
    return "";
  }

  std::string content(reinterpret_cast<char *>(memory.data()),
                      std::min(memory.size(), length));
  return content.c_str();
}

unsigned long long read_pointer(pid_t pid, unsigned long long address) {
  auto memory = read_memory(pid, address, sizeof(unsigned long long));
  return *reinterpret_cast<unsigned long long *>(memory.data());
}

// Read null pointer terminated array.
std::vector<std::string> read_null_pointer_terminated_array(
    pid_t pid, unsigned long long address, const int max_item_len, const int max_array_len) {
  std::vector<std::string> result;

  for (int i = 0; i < max_array_len; ++i) {
    auto ptr = read_pointer(pid, address);
    if (ptr == 0) {
      break;
    }
    auto value = read_string(pid, ptr, max_item_len);
    result.push_back(value);
    address += sizeof(unsigned long long);
  }

  return result;
}
