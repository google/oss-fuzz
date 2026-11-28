/* Copyright 2026 Reza Jelveh
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

size_t get_limit_from_env(const char* env_name);

int g_log_level = 0;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char value[128];
    size_t len = size < sizeof(value) - 1 ? size : sizeof(value) - 1;
    memcpy(value, data, len);
    value[len] = '\0';

    setenv("CUDA_DEVICE_MEMORY_LIMIT", value, 1);
    get_limit_from_env("CUDA_DEVICE_MEMORY_LIMIT");
    setenv("CUDA_DEVICE_SM_LIMIT", value, 1);
    get_limit_from_env("CUDA_DEVICE_SM_LIMIT");

    /* Short name reaches the fixed-offset env_name[12] access. */
    setenv("A", value, 1);
    get_limit_from_env("A");

    unsetenv("CUDA_DEVICE_MEMORY_LIMIT");
    unsetenv("CUDA_DEVICE_SM_LIMIT");
    unsetenv("A");
    return 0;
}
