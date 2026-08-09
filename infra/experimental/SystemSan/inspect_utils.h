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


/* POSIX */
#include <unistd.h>

#include <string>
#include <vector>

// Structure to know which thread id triggered the bug.
struct ThreadParent {
  // Parent thread ID, ie creator.
  pid_t parent_tid;
  // Current thread ID ran exec to become another process.
  bool ran_exec = false;

  ThreadParent() : parent_tid(0) {}
  ThreadParent(pid_t tid) : parent_tid(tid) {}
};

std::vector<std::byte> read_memory(pid_t pid, unsigned long long address,
                                   size_t size);

void report_bug(std::string bug_type, pid_t tid);
