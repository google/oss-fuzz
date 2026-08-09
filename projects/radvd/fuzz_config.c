// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "radvd.h"

// Mock functions needed for linking
int sock = -1;

// radvd.h declares these, but we might need to define them if we don't link radvd.o
// However, we will link against objects that might need them.

int LL_DEBUG_LOG = 0;
int log_method = L_STDERR;
char *conf_file = NULL;
char *pname = "fuzz_config";

// We need to mock logging functions to avoid cluttering output
void dlog(int level, int flevel, char const *fmt, ...) {}
void flog(int level, char const *fmt, ...) {}
void set_debuglevel(int level) {}
int get_debuglevel(void) { return 0; }

// We need readin_config
struct Interface *readin_config(char const *path);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char filename[] = "/tmp/fuzz-config-XXXXXX";
    int fd = mkstemp(filename);
    if (fd < 0) {
        return 0;
    }
    write(fd, data, size);
    close(fd);

    struct Interface *ifaces = readin_config(filename);
    
    if (ifaces) {
        free_ifaces(ifaces);
    }
    
    unlink(filename);
    return 0;
}
