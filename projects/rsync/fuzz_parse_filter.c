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
 */

#include "rsync.h"
#include <setjmp.h>

static jmp_buf fuzz_exit_jmp;

/* These are defined in main.c which we don't link against */
int am_receiver = 0;
int am_generator = 0;
int local_server = 0;
mode_t orig_umask = 022;
int batch_gen_fd = -1;
int sender_keeps_checksum = 0;
char *raw_argv[1] = {NULL};
int raw_argc = 0;
int cooked_argc = 0;
char **cooked_argv = NULL;
uid_t our_uid = 0;
gid_t our_gid = 0;
int daemon_connection = 0;

/* Stubs for functions defined in main.c */
void remember_children(UNUSED(int val)) {}
void start_server(UNUSED(int f_in), UNUSED(int f_out),
                  UNUSED(int argc), UNUSED(char *argv[])) {}
int client_run(UNUSED(int f_in), UNUSED(int f_out),
               UNUSED(pid_t pid), UNUSED(int argc), UNUSED(char *argv[])) { return 0; }
pid_t wait_process(UNUSED(pid_t pid), UNUSED(int *status_ptr),
                   UNUSED(int flags)) { return -1; }
int shell_exec(UNUSED(const char *cmd)) { return -1; }
void read_del_stats(UNUSED(int f)) {}
void write_del_stats(UNUSED(int f)) {}

/* Stubs for cleanup.c which we exclude to avoid exit() calls */
pid_t cleanup_child_pid = -1;
int cleanup_got_literal = 0;
int called_from_signal_handler = 0;
BOOL flush_ok_after_signal = False;
NORETURN void _exit_cleanup(UNUSED(int code), UNUSED(const char *file), UNUSED(int line)) {
    longjmp(fuzz_exit_jmp, 1);
}
void cleanup_disable(void) {}
void cleanup_set(UNUSED(const char *fnametmp), UNUSED(const char *fname),
                 UNUSED(struct file_struct *file), UNUSED(int fd_r), UNUSED(int fd_w)) {}
void cleanup_set_pid(UNUSED(pid_t pid)) {}
void close_all(void) {}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1 || size > 8192)
        return 0;

    /* Null-terminate the input */
    char *input = (char *)malloc(size + 1);
    if (!input)
        return 0;

    memcpy(input, data, size);
    input[size] = '\0';

    /* Use setjmp to catch rsync's exit_cleanup() calls */
    if (setjmp(fuzz_exit_jmp) != 0) {
        free(input);
        return 0;
    }

    /* Initialize a fresh filter list */
    filter_rule_list flist = { .head = NULL, .tail = NULL, .debug_type = "" };

    /* Parse the input as a filter rule string */
    parse_filter_str(&flist, input, rule_template(0), 0);

    /* Also try with OLD_PREFIXES flag for compatibility parsing */
    filter_rule_list flist2 = { .head = NULL, .tail = NULL, .debug_type = "" };
    parse_filter_str(&flist2, input, rule_template(FILTRULE_INCLUDE), XFLG_OLD_PREFIXES);

    /* Try with WORD_SPLIT (like daemon config parsing) */
    filter_rule_list flist3 = { .head = NULL, .tail = NULL, .debug_type = "" };
    parse_filter_str(&flist3, input,
                     rule_template(FILTRULE_WORD_SPLIT), 0);

    /* Exercise check_filter if we got any rules */
    if (flist.head) {
        check_filter(&flist, FINFO, "test/path/file.c", 0);
        check_filter(&flist, FINFO, "test/path/dir", NAME_IS_DIR);
        check_filter(&flist, FINFO, ".hidden", 0);
    }

    free(input);

    return 0;
}
