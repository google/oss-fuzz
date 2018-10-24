/*
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <stdint.h>
#include <stdlib.h>

#include <memory>

#include <clamav.h>


void clamav_message_callback(enum cl_msg severity, const char *fullmsg,
                             const char *msg, void *context) {
}

class ClamAVState {
public:
    ClamAVState() {
        // Silence all the log messages, none of them are meaningful.
        cl_set_clcb_msg(clamav_message_callback);

        cl_init(CL_INIT_DEFAULT);
        engine = cl_engine_new();
        cl_engine_compile(engine);
    }

    ~ClamAVState() {
        cl_engine_free(engine);
    }

    struct cl_engine *engine;
};

// Global with static initializer to setup an engine so we don't need to do
// that on each execution.
ClamAVState kClamAVState;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    cl_fmap_t *clamav_data = cl_fmap_open_memory(data, size);

    unsigned int parseopt =
#if defined(CLAMAV_FUZZ_ARCHIVE)
        CL_SCAN_PARSE_ARCHIVE;
#elif defined(CLAMAV_FUZZ_MAIL)
        CL_SCAN_PARSE_MAIL;
#elif defined(CLAMAV_FUZZ_OLE2)
        CL_SCAN_PARSE_OLE2;
#elif defined(CLAMAV_FUZZ_PDF)
        CL_SCAN_PARSE_PDF;
#elif defined(CLAMAV_FUZZ_HTML)
        CL_SCAN_PARSE_HTML;
#elif defined(CLAMAV_FUZZ_PE)
        CL_SCAN_PARSE_PE;
#elif defined(CLAMAV_FUZZ_ELF)
        CL_SCAN_PARSE_ELF;
#elif defined(CLAMAV_FUZZ_SWF)
        CL_SCAN_PARSE_SWF;
#elif defined(CLAMAV_FUZZ_XMLDOCS)
        CL_SCAN_PARSE_XMLDOCS;
#elif defined(CLAMAV_FUZZ_HWP3)
        CL_SCAN_PARSE_HWP3;
#else
        ~0;
#endif
    struct cl_scan_options options = {0};
    options.parse = parseopt;

    const char *virus_name = nullptr;
    unsigned long scanned = 0;
    cl_scanmap_callback(
        clamav_data,
        nullptr,
        &virus_name,
        &scanned,
        kClamAVState.engine,
        &options,
        nullptr
    );

    cl_fmap_close(clamav_data);

    return 0;
}
