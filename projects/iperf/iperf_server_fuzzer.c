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
#include <unistd.h>
#include <sys/socket.h>
#include "iperf_config.h"
#include "iperf_api.h"
#include "iperf.h"

// Global jump buffer for error handling
static jmp_buf fuzz_jmp_buf;

// Wrapper for iperf_errexit
void __wrap_iperf_errexit(struct iperf_test *test, const char *format, ...) {
    longjmp(fuzz_jmp_buf, 1);
}

// Wrapper for iperf_exit
void __wrap_iperf_exit(struct iperf_test *test, int exit_code, const char *format, va_list argp) {
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
    int pipefd[2];

    if (size == 0) {
        return 0;
    }

    // Create a pipe to feed data to the server
    if (pipe(pipefd) == -1) {
        return 0;
    }

    // Write data to the pipe
    // We write to the write end, and the server reads from the read end
    // Note: if size is larger than pipe buffer, this might block.
    // But for fuzzing inputs (usually small), it should be fine.
    // If it blocks, we might need a separate thread or non-blocking write.
    // For now, let's assume small inputs or large enough pipe buffer.
    // Linux pipe buffer is usually 64KB.
    if (write(pipefd[1], data, size) != size) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }
    // Close write end so the reader sees EOF after reading all data
    // But iperf might expect more data and timeout.
    // If we close it, Nread might return 0 (EOF).
    // iperf_handle_message_server handles EOF by returning 0.
    // However, if we are in the middle of reading a message, it might error out.
    // Let's keep it open? No, if we keep it open and don't write, Nread will timeout.
    // Closing it is better for speed, but might not exercise the timeout logic.
    // But we want to fuzz the parsing logic, so EOF is fine.
    // Actually, if we close it, read returns 0 immediately.
    // If we want to simulate a stream, we should write and then close.
    close(pipefd[1]);

    // Initialize iperf test
    test = iperf_new_test();
    if (!test) {
        close(pipefd[0]);
        return 0;
    }
    iperf_defaults(test);
    
    // Set the control socket to the read end of the pipe
    test->ctrl_sck = pipefd[0];
    test->role = 's'; // Server role

    // Set jump point for error handling
    if (setjmp(fuzz_jmp_buf) == 0) {
        // Call the target function
        // We loop until it returns error or done, or we run out of data (handled by Nread returning 0 or error)
        // But iperf_handle_message_server reads one state message.
        // If state is PARAM_EXCHANGE, it reads more.
        // We can call it once.
        iperf_handle_message_server(test);
    } else {
        // We jumped here from an exit call
    }

    // Cleanup
    if (test) {
        // iperf_free_test closes ctrl_sck if it's not -1.
        // But we assigned pipefd[0] to it.
        // So iperf_free_test will close it.
        // We should check if we need to close it manually if iperf_free_test doesn't.
        // iperf_free_test calls iperf_free_stream which closes socket?
        // No, ctrl_sck is in iperf_test.
        // Let's check iperf_free_test.
        // It doesn't seem to close ctrl_sck explicitly in the snippet I saw.
        // But let's assume it might.
        // To be safe, we can set it to -1 before freeing if we want to close it ourselves,
        // or just let the OS clean up if we leak a FD (fuzzer runs in loop, so leaks are bad).
        // Let's close it if it's open.
        if (test->ctrl_sck != -1) {
            close(test->ctrl_sck);
            test->ctrl_sck = -1;
        }
        iperf_free_test(test);
    } else {
        close(pipefd[0]);
    }

    return 0;
}
