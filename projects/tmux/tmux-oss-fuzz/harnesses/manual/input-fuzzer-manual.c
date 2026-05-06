/*
 * input-fuzzer-manual.c
 *
 * Manual libFuzzer harness for tmux input parsing (input_parse_buffer).
 *
 * Design intent:
 *   - Fixed, stable pane dimensions (not derived from fuzz input).
 *   - Input is passed directly to input_parse_buffer without an intermediate
 *     structured-consumption layer.
 *   - All cleanup is unconditional (no errx on setup failures other than a
 *     hard /dev/null open that genuinely cannot proceed without).
 *   - Minimal side effects: only global option state set in Initialize;
 *     nothing else persists across iterations.
 *
 * Contrast with harnesses/generated/input-fuzzer-fuzzgen.c which derives
 * pane dimensions and other parameters from the fuzz input itself.
 *
 * Contract compliance (see docs/input-parse-harness-contract.md):
 *   [1] Target function   : input_parse_buffer
 *   [2] libFuzzer entry   : LLVMFuzzerTestOneInput + LLVMFuzzerInitialize
 *   [3] Max input size    : FUZZER_MAXLEN = 512
 *   [4] Global init       : global_environ, global_options, global_s_options,
 *                           global_w_options, libevent, socket_path
 *   [5] Object lifecycle  : window + pane + bufferevent pair per iteration
 *   [6] Post-parse drain  : cmdq_next loop + event_base_loop NONBLOCK
 *   [7] Cleanup           : window_remove_ref + bufferevent_free (both ends)
 *   [8] Determinism       : no network I/O; no persistent per-input state
 *   [9] Build / runtime   : accepts -max_total_time and standard libFuzzer flags
 */

#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>

#include "tmux.h"

/* ── contract constants ──────────────────────────────────────────────────── */

#define FUZZER_MAXLEN  512
#define PANE_WIDTH      80
#define PANE_HEIGHT     25

/* ── module-level state (initialised once, survives across iterations) ───── */

struct event_base *libevent;

/* ── fuzz entry point ────────────────────────────────────────────────────── */

int
LLVMFuzzerTestOneInput(const u_char *data, size_t size)
{
	struct bufferevent	*vpty[2];
	struct window		*w;
	struct window_pane	*wp;
	int			 error;

	/* Enforce max input bound deterministically (drop oversized inputs). */
	if (size > FUZZER_MAXLEN)
		return 0;

	/* ── per-iteration setup ─────────────────────────────────────────── */

	w = window_create(PANE_WIDTH, PANE_HEIGHT, 0, 0);
	if (w == NULL)
		return 0;

	wp = window_add_pane(w, NULL, 0, 0);
	if (wp == NULL) {
		window_remove_ref(w, __func__);
		return 0;
	}

	if (bufferevent_pair_new(libevent, BEV_OPT_CLOSE_ON_FREE, vpty) != 0) {
		window_remove_ref(w, __func__);
		return 0;
	}

	wp->ictx = input_init(wp, vpty[0], NULL, NULL);
	window_add_ref(w, __func__);

	wp->fd = open("/dev/null", O_WRONLY);
	if (wp->fd == -1)
		errx(1, "open(\"/dev/null\") failed");
	wp->event = bufferevent_new(wp->fd, NULL, NULL, NULL, NULL);

	/* ── core parse call ─────────────────────────────────────────────── */

	input_parse_buffer(wp, (u_char *)data, size);

	/* ── post-parse drain ────────────────────────────────────────────── */

	while (cmdq_next(NULL) != 0)
		;

	error = event_base_loop(libevent, EVLOOP_NONBLOCK);
	if (error == -1)
		errx(1, "event_base_loop failed");

	/* ── cleanup ─────────────────────────────────────────────────────── */

	assert(w->references == 1);
	window_remove_ref(w, __func__);

	bufferevent_free(vpty[0]);
	bufferevent_free(vpty[1]);

	return 0;
}

/* ── one-time initialisation ─────────────────────────────────────────────── */

int
LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
	const struct options_table_entry	*oe;

	global_environ   = environ_create();
	global_options   = options_create(NULL);
	global_s_options = options_create(NULL);
	global_w_options = options_create(NULL);

	for (oe = options_table; oe->name != NULL; oe++) {
		if (oe->scope & OPTIONS_TABLE_SERVER)
			options_default(global_options, oe);
		if (oe->scope & OPTIONS_TABLE_SESSION)
			options_default(global_s_options, oe);
		if (oe->scope & OPTIONS_TABLE_WINDOW)
			options_default(global_w_options, oe);
	}

	libevent = osdep_event_init();

	options_set_number(global_w_options, "monitor-bell", 0);
	options_set_number(global_w_options, "allow-rename",  1);
	options_set_number(global_options,   "set-clipboard", 2);

	socket_path = xstrdup("dummy");

	return 0;
}

/* ── libFuzzer driver entry (fuzz-mode builds only) ─────────────────────── */

#ifdef NEED_FUZZING
int LLVMFuzzerRunDriver(int *argc, char ***argv,
    int (*UserCb)(const unsigned char *Data, size_t Size));

int
main(int argc, char **argv)
{
	return (LLVMFuzzerRunDriver(&argc, &argv,
	    (int (*)(const unsigned char *, size_t))LLVMFuzzerTestOneInput));
}
#endif
