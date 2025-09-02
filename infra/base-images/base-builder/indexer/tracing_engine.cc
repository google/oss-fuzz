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

// This variant does function level tracing and dumps a list of symbolized
// functions visited (in order) to TRACE_DUMP_FILE. Each function is only ever
// recorded once. To make this work, we need to compile with
// -fsanitize-coverage=trace-pc-guard,func

#include <assert.h>
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

constexpr int kMaxTraceSize = 64 * 1024;

struct CoverageData {
  void* pcs[kMaxTraceSize];
  size_t idx = 0;
  // TODO: b/441647761 - Handle multiple threads.
  pid_t main_thread_id;
  bool finished = false;
};

static CoverageData* coverage_data;

static pid_t GetTID() { return static_cast<pid_t>(syscall(SYS_gettid)); }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t n);

extern "C" __attribute__((weak)) int LLVMFuzzerInitialize(int* argc,
                                                          char*** argv);

// Projects can call LLVMFuzzerMutate, but should only do it from
// LLVMFuzzerCustomMutator, which should be called from the fuzzing engine (we
// don't need to).
extern "C" size_t LLVMFuzzerMutate([[maybe_unused]] uint8_t* Data,
                                   [[maybe_unused]] size_t Size,
                                   [[maybe_unused]] size_t MaxSize) {
  fprintf(stderr, "LLVMFuzzerMutate was called. This should never happen.\n");
  __builtin_trap();
}

extern "C" void __sanitizer_cov_trace_pc_guard_init(uint32_t* start,
                                                    uint32_t* stop) {
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

namespace {

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
    char outbuf[1024];
    __sanitizer_symbolize_pc(coverage_data->pcs[i], "%f", outbuf,
                             sizeof(outbuf));
    // Skip standard libraries.
    if (strncmp(outbuf, "std::", 5) == 0) continue;
    write(fd, outbuf, strnlen(outbuf, sizeof(outbuf)));
    write(fd, "\n", 1);
  }

  close(fd);
}

void Init() {
  coverage_data = new CoverageData();
  // For now, only record PCs from the main thread.
  coverage_data->main_thread_id = GetTID();
  // Dump coverage on exit.
  atexit(WriteTrace);
  __sanitizer_set_death_callback(WriteTrace);
}

}  // namespace

int main(int argc, char* argv[]) {
  Init();

  if (LLVMFuzzerInitialize) {
    LLVMFuzzerInitialize(&argc, &argv);
  }

  if (argc != 2) {
    // Special-case because curl invokes the fuzzer binaries without arguments
    // during make, and will fail if they don't return success.
    if (strstr(argv[0], "curl_fuzzer")) {
      fprintf(stderr, "Exiting early for curl_fuzzer\n");
      exit(EXIT_SUCCESS);
    }

    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  int fd = open(argv[1], O_RDONLY);
  if (fd == -1) {
    perror("open");
    exit(EXIT_FAILURE);
  }

  struct stat st;
  if (fstat(fd, &st) == -1) {
    perror("stat");
    exit(EXIT_FAILURE);
  }

  size_t size = static_cast<size_t>(st.st_size);
  uint8_t* data = static_cast<uint8_t*>(malloc(size));
  if (!data) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  size_t bytes_read = 0;
  while (bytes_read < size) {
    ssize_t res = read(fd, data + bytes_read, size - bytes_read);
    if (res == -1) {
      perror("read");
      exit(EXIT_FAILURE);
    }
    if (res == 0) {
      fprintf(stderr, "Unexpected EOF.\n");
      exit(EXIT_FAILURE);
    }
    bytes_read += static_cast<size_t>(res);
  }
  close(fd);

  int res = LLVMFuzzerTestOneInput(data, size);
  free(data);
  return res;
}
