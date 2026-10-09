/*
 * Copyright 2026 Google LLC
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
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <security/pam_modules.h>
#include <security/pam_ext.h>

// Mocking some functions that might be problematic
int lckpwdf(void) { return 0; }
int ulckpwdf(void) { return 0; }

// The function we want to fuzz
int update_pass_special_file(const pam_handle_t *pamh, const char *keyfilename,
			     const char *filename, const char *forwho,
			     const char *towhat);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) return 0;

    char key_file[] = "/tmp/fuzz_key_XXXXXX";
    int key_fd = mkstemp(key_file);
    if (key_fd == -1) return 0;
    // key file must be 8 bytes as per pam_ipmisave.c: MAX_KEY_SIZE
    uint8_t key_data[8] = {0};
    if (size >= 8) {
        memcpy(key_data, data, 8);
        data += 8;
        size -= 8;
    }
    write(key_fd, key_data, 8);
    close(key_fd);

    char pass_file[] = "/tmp/fuzz_pass_XXXXXX";
    int pass_fd = mkstemp(pass_file);
    if (pass_fd == -1) {
        unlink(key_file);
        return 0;
    }
    if (size > 0) {
        // Use half of remaining data for the initial pass file content
        size_t initial_file_size = size / 2;
        write(pass_fd, data, initial_file_size);
        data += initial_file_size;
        size -= initial_file_size;
    }
    close(pass_fd);

    if (size < 2) {
        unlink(key_file);
        unlink(pass_file);
        return 0;
    }

    // Use the rest for username and password
    size_t user_len = size / 2;
    char *user = malloc(user_len + 1);
    memcpy(user, data, user_len);
    user[user_len] = '\0';
    data += user_len;
    size -= user_len;

    char *pass = malloc(size + 1);
    memcpy(pass, data, size);
    pass[size] = '\0';

    // Call the function
    update_pass_special_file(NULL, key_file, pass_file, user, pass);

    free(user);
    free(pass);
    unlink(key_file);
    unlink(pass_file);

    return 0;
}
