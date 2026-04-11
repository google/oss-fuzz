/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************************
 *
 * occt_fuzz_iges.cpp -- libFuzzer harness for OpenCASCADE IGES parser.
 *
 * Writes fuzzer-supplied bytes to a tmp file in /dev/shm, then calls
 * IGESControl_Reader::ReadFile() which dispatches into the IGES parser
 * (analiges.c, liriges.c, structiges.c). Per-iteration cost is one
 * mkstemp + write + parse + close + unlink on tmpfs.
 */

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <IGESControl_Reader.hxx>
#include <IGESData_IGESModel.hxx>

#define OCCT_FUZZ_MAX_SIZE (4u * 1024u * 1024u)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > OCCT_FUZZ_MAX_SIZE) return 0;

    char path[] = "/dev/shm/occt_iges_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;

    ssize_t w = write(fd, data, size);
    close(fd);
    if (w != (ssize_t)size) {
        unlink(path);
        return 0;
    }

    try {
        IGESControl_Reader reader;
        reader.ReadFile(path);
    } catch (...) {
        // Swallow all exceptions -- we only care about ASan/UBSan signals
    }

    unlink(path);
    return 0;
}
