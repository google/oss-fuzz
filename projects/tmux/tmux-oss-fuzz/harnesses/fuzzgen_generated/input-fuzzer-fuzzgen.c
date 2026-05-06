/*
 * FuzzGen-style harness for tmux input parsing
 *
 * This harness is designed to mimic what FuzzGen would generate,
 * using a FuzzedDataProvider approach to structured fuzzing.
 *
 * Key differences from the manual harness:
 * 1. Uses structured input consumption (FuzzedDataProvider pattern)
 * 2. Derives configuration from fuzz input
 * 3. Variable pane dimensions
 * 4. More exploration of code paths
 *
 * Copyright 2024 - Educational purposes
 * License: Same as tmux (ISC License)
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#include "tmux.h"

/* 
 * FuzzedDataProvider-style helper functions
 * 
 * FuzzGen generates similar consumption patterns based on
 * analysis of how the API is used by consumer programs.
 */
struct fuzzed_data {
    const uint8_t *data;
    size_t size;
    size_t offset;
};

static void fd_init(struct fuzzed_data *fd, const uint8_t *data, size_t size) {
    fd->data = data;
    fd->size = size;
    fd->offset = 0;
}

static size_t fd_remaining(struct fuzzed_data *fd) {
    return fd->size - fd->offset;
}

static uint8_t fd_consume_byte(struct fuzzed_data *fd) {
    if (fd->offset >= fd->size)
        return 0;
    return fd->data[fd->offset++];
}

static uint16_t fd_consume_uint16(struct fuzzed_data *fd) {
    uint16_t val = 0;
    if (fd_remaining(fd) >= 2) {
        val = fd->data[fd->offset] | (fd->data[fd->offset + 1] << 8);
        fd->offset += 2;
    }
    return val;
}

static size_t fd_consume_bytes(struct fuzzed_data *fd, uint8_t *out, size_t max) {
    size_t remaining = fd_remaining(fd);
    size_t to_copy = remaining < max ? remaining : max;
    memcpy(out, fd->data + fd->offset, to_copy);
    fd->offset += to_copy;
    return to_copy;
}

static uint32_t fd_consume_uint32_in_range(struct fuzzed_data *fd, uint32_t min, uint32_t max) {
    if (fd_remaining(fd) < 4)
        return min;
    
    uint32_t val = 0;
    for (int i = 0; i < 4; i++) {
        val = (val << 8) | fd_consume_byte(fd);
    }
    
    if (max <= min)
        return min;
    
    return min + (val % (max - min + 1));
}

static int fd_consume_bool(struct fuzzed_data *fd) {
    return fd_consume_byte(fd) & 1;
}

/* Configuration parameters */
#define MAX_INPUT_LEN 512
#define MIN_PANE_WIDTH 10
#define MAX_PANE_WIDTH 200
#define MIN_PANE_HEIGHT 5
#define MAX_PANE_HEIGHT 100

struct event_base *libevent;

/*
 * LLVMFuzzerTestOneInput - FuzzGen style entry point
 *
 * This function uses structured fuzzing to:
 * 1. Derive pane dimensions from fuzz input
 * 2. Configure options based on fuzz input
 * 3. Parse the escape sequences
 * 4. Exercise additional code paths based on input
 *
 * FuzzGen would analyze how input_parse_buffer is called
 * by consumer programs and generate appropriate setup code.
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct fuzzed_data fd;
    struct bufferevent *vpty[2];
    struct window *w;
    struct window_pane *wp;
    uint8_t input_buf[MAX_INPUT_LEN];
    size_t input_len;
    int error;
    int pane_width, pane_height;
    int flags;
    
    /* Need minimum input for structured consumption */
    if (size < 10)
        return 0;
    
    fd_init(&fd, data, size);
    
    /* 
     * Derive pane dimensions from fuzz input.
     * FuzzGen identifies these as parameters from API analysis.
     */
    pane_width = fd_consume_uint32_in_range(&fd, MIN_PANE_WIDTH, MAX_PANE_WIDTH);
    pane_height = fd_consume_uint32_in_range(&fd, MIN_PANE_HEIGHT, MAX_PANE_HEIGHT);
    
    /*
     * Derive flags from fuzz input.
     * FuzzGen would identify these from window_create usage.
     */
    flags = fd_consume_byte(&fd) & 0x0F;  /* Use lower 4 bits for flags */
    
    /* Create window with derived dimensions */
    w = window_create(pane_width, pane_height, 0, flags);
    if (w == NULL)
        return 0;
    
    wp = window_add_pane(w, NULL, 0, 0);
    bufferevent_pair_new(libevent, BEV_OPT_CLOSE_ON_FREE, vpty);
    
    /* Initialize input context - the main object being fuzzed */
    wp->ictx = input_init(wp, vpty[0], NULL, NULL);
    window_add_ref(w, __func__);
    
    /* Output goes to /dev/null */
    wp->fd = open("/dev/null", O_WRONLY);
    if (wp->fd == -1)
        errx(1, "open(\"/dev/null\") failed");
    
    wp->event = bufferevent_new(wp->fd, NULL, NULL, NULL, NULL);
    
    /*
     * FuzzGen might configure runtime options based on observed usage.
     * We use fuzz input to decide on option values.
     */
    if (fd_consume_bool(&fd)) {
        options_set_number(global_w_options, "allow-rename", 1);
    }
    
    if (fd_consume_bool(&fd)) {
        options_set_number(global_options, "set-clipboard", 
                          fd_consume_uint32_in_range(&fd, 0, 2));
    }
    
    /* Consume remaining bytes as escape sequence input */
    input_len = fd_consume_bytes(&fd, input_buf, MAX_INPUT_LEN);
    
    /* 
     * THE CORE PARSING CALL
     * This is what FuzzGen would identify as the main API entry point
     * based on control flow and data flow analysis.
     */
    input_parse_buffer(wp, input_buf, input_len);
    
    /* 
     * Process any queued commands.
     * FuzzGen identifies this from observer programs that
     * call cmdq_next after input processing.
     */
    while (cmdq_next(NULL) != 0)
        ;
    
    /* 
     * Run event loop iteration.
     * FuzzGen identifies this pattern from libevent usage.
     */
    error = event_base_loop(libevent, EVLOOP_NONBLOCK);
    if (error == -1)
        errx(1, "event_base_loop failed");
    
    /* Cleanup - proper teardown prevents leaks in long-running fuzzing */
    assert(w->references == 1);
    window_remove_ref(w, __func__);
    
    bufferevent_free(vpty[0]);
    bufferevent_free(vpty[1]);
    
    return 0;
}

/*
 * LLVMFuzzerInitialize - One-time setup
 *
 * FuzzGen generates initialization code based on observed
 * API usage patterns in consumer programs. It identifies:
 * - Global state that must be initialized
 * - Dependencies between API calls
 * - Required configuration
 */
int
LLVMFuzzerInitialize(__attribute__((unused)) int *argc, 
                     __attribute__((unused)) char ***argv)
{
    const struct options_table_entry *oe;
    
    /* 
     * Initialize global environment.
     * FuzzGen identifies environ_create() as required initialization
     * from analysis of main() and server startup.
     */
    global_environ = environ_create();
    
    /* 
     * Initialize options structures.
     * FuzzGen identifies these from options_* API usage.
     */
    global_options = options_create(NULL);
    global_s_options = options_create(NULL);
    global_w_options = options_create(NULL);
    
    /* 
     * Set default options from options table.
     * FuzzGen identifies this loop pattern from server-options.c
     */
    for (oe = options_table; oe->name != NULL; oe++) {
        if (oe->scope & OPTIONS_TABLE_SERVER)
            options_default(global_options, oe);
        if (oe->scope & OPTIONS_TABLE_SESSION)
            options_default(global_s_options, oe);
        if (oe->scope & OPTIONS_TABLE_WINDOW)
            options_default(global_w_options, oe);
    }
    
    /* 
     * Initialize event loop.
     * FuzzGen identifies osdep_event_init() as required from libevent usage.
     */
    libevent = osdep_event_init();
    
    /* 
     * Configure options for maximum code coverage.
     * These could also be derived from fuzz input.
     */
    options_set_number(global_w_options, "monitor-bell", 0);
    options_set_number(global_w_options, "allow-rename", 1);
    options_set_number(global_options, "set-clipboard", 2);
    
    /* Dummy socket path - not used but required by some code paths */
    socket_path = xstrdup("dummy");
    
    return 0;
}
