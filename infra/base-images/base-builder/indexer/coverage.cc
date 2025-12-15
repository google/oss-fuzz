// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fcntl.h>
#include <sanitizer/common_interface_defs.h>
#include <sanitizer/coverage_interface.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

constexpr int kMaxTraceSize = 64 * 1024;

struct CoverageData {
  void* pcs[kMaxTraceSize];
  size_t idx;
  // TODO: b/441647761 - Handle multiple threads.
  pid_t main_thread_id;
  bool finished;
};

static CoverageData* coverage_data;

bool IsStandardLibrary(const char* file_path) {
  return (strstr(file_path, "include/c++/v1") ||
          strncmp(file_path, "/usr/include", 12) == 0 ||
          strstr(file_path, "libc++/src/include") ||
          strstr(file_path, "/absl/"));
}

void WriteTrace() {
  coverage_data->finished = true;
  char* trace_dump_file = getenv("TRACE_DUMP_FILE");
  if (!trace_dump_file) {
    return;
  }

  int fd = open(trace_dump_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd == -1) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  // TODO: b/441647761 - This format likely needs iteration. This just prints
  // symbolized function names, but this could still be ambiguous.
  for (size_t i = 0; i < coverage_data->idx; ++i) {
    char symbol[1024];
    char file_path[1024];

    // This always null terminates.
    __sanitizer_symbolize_pc(coverage_data->pcs[i], "%f", symbol,
                             sizeof(symbol));
    __sanitizer_symbolize_pc(coverage_data->pcs[i], "%s", file_path,
                             sizeof(file_path));

    if (IsStandardLibrary(file_path)) continue;

    write(fd, symbol, strlen(symbol));
    write(fd, "\n", 1);
  }

  close(fd);
}

pid_t GetTID() { return static_cast<pid_t>(syscall(SYS_gettid)); }

void Init() {
  coverage_data = static_cast<CoverageData*>(malloc(sizeof(CoverageData)));
  coverage_data->finished = false;
  coverage_data->idx = 0;
  // For now, only record PCs from the main thread.
  coverage_data->main_thread_id = GetTID();
  // Dump coverage on exit.
  atexit(WriteTrace);
  __sanitizer_set_death_callback(WriteTrace);
}

}  // namespace

extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t* start,
                                                    uint32_t* stop) {
  Init();
  static uint32_t N;  // Counter for the guards.
  if (start == stop || *start) return;
  for (uint32_t* x = start; x < stop; x++) *x = ++N;
}

extern "C" void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  thread_local bool in_callback = false;

  if (!coverage_data || coverage_data->finished) return;
  if (*guard == 0) return;
  if (in_callback) return;
  in_callback = true;

  class ResetInCallback {
   public:
    ~ResetInCallback() { in_callback = false; }
  } reset_in_callback;

  thread_local pid_t thread_id = GetTID();
  if (thread_id != coverage_data->main_thread_id) {
    return;
  }

  if (coverage_data->idx >= kMaxTraceSize) {
    return;
  }

  *guard = 0;  // Don't trace the same PC more than once.
  coverage_data->pcs[coverage_data->idx++] =
      reinterpret_cast<void*>(__builtin_return_address(0));
}
