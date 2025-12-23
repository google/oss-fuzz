// Copyright 2025 Google LLC
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include "iperf_config.h"
#include "iperf_api.h"

// Global jump buffer for error handling
static jmp_buf fuzz_jmp_buf;

// Wrapper for iperf_errexit
void __wrap_iperf_errexit(struct iperf_test *test, const char *format, ...) {
    va_list argp;
    va_start(argp, format);
    // We can optionally print the error if we want to debug, but for fuzzing we usually suppress it
    // vfprintf(stderr, format, argp);
    va_end(argp);
    longjmp(fuzz_jmp_buf, 1);
}

// Wrapper for iperf_exit
void __wrap_iperf_exit(struct iperf_test *test, int exit_code, const char *format, va_list argp) {
    // vfprintf(stderr, format, argp);
    longjmp(fuzz_jmp_buf, 1);
}

// Wrapper for standard exit
void __wrap_exit(int status) {
    longjmp(fuzz_jmp_buf, 1);
}

// Wrapper for abort
void __wrap_abort(void) {
    longjmp(fuzz_jmp_buf, 1);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct iperf_test *test = NULL;
    char *str_data = NULL;
    int argc = 0;
    char **argv = NULL;
    char *token;
    char *saveptr;

    if (size == 0) {
        return 0;
    }

    // Create a null-terminated string from the input data
    str_data = (char *)malloc(size + 1);
    if (!str_data) {
        return 0;
    }
    memcpy(str_data, data, size);
    str_data[size] = '\0';

    // Initialize iperf test
    test = iperf_new_test();
    if (!test) {
        free(str_data);
        return 0;
    }
    iperf_defaults(test);

    // Parse the input string into argc and argv
    argc = 1;
    argv = (char **)malloc(sizeof(char *) * (argc + 1));
    argv[0] = strdup("iperf3");

    token = strtok_r(str_data, " ", &saveptr);
    while (token != NULL) {
        argc++;
        char **new_argv = (char **)realloc(argv, sizeof(char *) * (argc + 1));
        if (!new_argv) {
            // Cleanup on allocation failure
            for (int i = 0; i < argc - 1; i++) {
                free(argv[i]);
            }
            free(argv);
            iperf_free_test(test);
            free(str_data);
            return 0;
        }
        argv = new_argv;
        argv[argc - 1] = strdup(token);
        token = strtok_r(NULL, " ", &saveptr);
    }
    argv[argc] = NULL;

    // Set jump point for error handling
    if (setjmp(fuzz_jmp_buf) == 0) {
        // Call the target function
        iperf_parse_arguments(test, argc, argv);
    } else {
        // We jumped here from an exit call
        // Just cleanup and return
    }

    // Cleanup
    if (test) {
        iperf_free_test(test);
    }
    if (argv) {
        for (int i = 0; i < argc; i++) {
            free(argv[i]);
        }
        free(argv);
    }
    free(str_data);

    return 0;
}
