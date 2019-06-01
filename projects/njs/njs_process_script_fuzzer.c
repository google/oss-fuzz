// Copyright 2019 Google LLC
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

#include <stddef.h>
#include <stdint.h>

#include <njs_core.h>
#include <njs_builtin.h>

// The vast majority of the code was copied from njs/njs_shell.c.

typedef struct {
    uint8_t                 disassemble;
    uint8_t                 interactive;
    uint8_t                 module;
    uint8_t                 quiet;
    uint8_t                 sandbox;
    uint8_t                 version;

    char                    *file;
    char                    *command;
    size_t                  n_paths;
    char                    **paths;
} njs_opts_t;


typedef struct {
    size_t                  index;
    size_t                  length;
    nxt_array_t             *completions;
    nxt_array_t             *suffix_completions;
    nxt_lvlhsh_each_t       lhe;

    enum {
       NJS_COMPLETION_VAR = 0,
       NJS_COMPLETION_SUFFIX,
       NJS_COMPLETION_GLOBAL
    }                       phase;
} njs_completion_t;


typedef struct {
    njs_vm_event_t          vm_event;
    nxt_queue_link_t        link;
} njs_ev_t;


typedef struct {
    njs_vm_t                *vm;

    nxt_lvlhsh_t            events;  /* njs_ev_t * */
    nxt_queue_t             posted_events;

    uint64_t                time;

    njs_completion_t        completion;
} njs_console_t;


static nxt_int_t njs_console_init(njs_vm_t *vm, njs_console_t *console);
static nxt_int_t njs_externals_init(njs_vm_t *vm, njs_console_t *console);
static nxt_int_t njs_interactive_shell(njs_opts_t *opts,
    njs_vm_opt_t *vm_options, nxt_str_t *line);
static njs_vm_t *njs_create_vm(njs_opts_t *opts, njs_vm_opt_t *vm_options);
static nxt_int_t njs_process_script(njs_console_t *console, njs_opts_t *opts,
    const nxt_str_t *script);

static njs_ret_t njs_ext_console_log(njs_vm_t *vm, njs_value_t *args,
    nxt_uint_t nargs, njs_index_t unused);
static njs_ret_t njs_ext_console_dump(njs_vm_t *vm, njs_value_t *args,
    nxt_uint_t nargs, njs_index_t unused);
static njs_ret_t njs_ext_console_help(njs_vm_t *vm, njs_value_t *args,
    nxt_uint_t nargs, njs_index_t unused);
static njs_ret_t njs_ext_console_time(njs_vm_t *vm, njs_value_t *args,
    nxt_uint_t nargs, njs_index_t unused);
static njs_ret_t njs_ext_console_time_end(njs_vm_t *vm, njs_value_t *args,
    nxt_uint_t nargs, njs_index_t unused);

static njs_host_event_t njs_console_set_timer(njs_external_ptr_t external,
    uint64_t delay, njs_vm_event_t vm_event);
static void njs_console_clear_timer(njs_external_ptr_t external,
    njs_host_event_t event);

static nxt_int_t lvlhsh_key_test(nxt_lvlhsh_query_t *lhq, void *data);
static void *lvlhsh_pool_alloc(void *pool, size_t size, nxt_uint_t nalloc);
static void lvlhsh_pool_free(void *pool, void *p, size_t size);


static njs_external_t  njs_ext_console[] = {

    { nxt_string("log"),
      NJS_EXTERN_METHOD,
      NULL,
      0,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      njs_ext_console_log,
      0 },

    { nxt_string("dump"),
      NJS_EXTERN_METHOD,
      NULL,
      0,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      njs_ext_console_dump,
      0 },

    { nxt_string("help"),
      NJS_EXTERN_METHOD,
      NULL,
      0,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      njs_ext_console_help,
      0 },

    { nxt_string("time"),
      NJS_EXTERN_METHOD,
      NULL,
      0,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      njs_ext_console_time,
      0 },

    { nxt_string("timeEnd"),
      NJS_EXTERN_METHOD,
      NULL,
      0,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      njs_ext_console_time_end,
      0 },
};

static njs_external_t  njs_externals[] = {

    { nxt_string("console"),
      NJS_EXTERN_OBJECT,
      njs_ext_console,
      nxt_nitems(njs_ext_console),
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      0 },
};


static const nxt_lvlhsh_proto_t  lvlhsh_proto  nxt_aligned(64) = {
    NXT_LVLHSH_LARGE_SLAB,
    0,
    lvlhsh_key_test,
    lvlhsh_pool_alloc,
    lvlhsh_pool_free,
};


static njs_vm_ops_t njs_console_ops = {
    njs_console_set_timer,
    njs_console_clear_timer
};


static njs_console_t  njs_console;


static nxt_int_t
njs_console_init(njs_vm_t *vm, njs_console_t *console)
{
    console->vm = vm;

    nxt_lvlhsh_init(&console->events);
    nxt_queue_init(&console->posted_events);

    console->time = UINT64_MAX;

    console->completion.completions = njs_vm_completions(vm, NULL);
    if (console->completion.completions == NULL) {
        return NXT_ERROR;
    }

    return NXT_OK;
}


static nxt_int_t
njs_externals_init(njs_vm_t *vm, njs_console_t *console)
{
    nxt_uint_t          ret;
    njs_value_t         *value;
    const njs_extern_t  *proto;

    static const nxt_str_t name = nxt_string("console");

    proto = njs_vm_external_prototype(vm, &njs_externals[0]);
    if (proto == NULL) {
        nxt_error("failed to add console proto\n");
        return NXT_ERROR;
    }

    value = nxt_mp_zalloc(vm->mem_pool, sizeof(njs_opaque_value_t));
    if (value == NULL) {
        return NXT_ERROR;
    }

    ret = njs_vm_external_create(vm, value, proto, console);
    if (ret != NXT_OK) {
        return NXT_ERROR;
    }

    ret = njs_vm_external_bind(vm, &name, value);
    if (ret != NXT_OK) {
        return NXT_ERROR;
    }

    ret = njs_console_init(vm, console);
    if (ret != NXT_OK) {
        return NXT_ERROR;
    }

    return NXT_OK;
}

static nxt_int_t
njs_interactive_shell(njs_opts_t *opts, njs_vm_opt_t *vm_options, nxt_str_t *line)
{
    njs_vm_t   *vm;

    vm = njs_create_vm(opts, vm_options);
    if (vm == NULL) {
        return NXT_ERROR;
    }

    njs_process_script(vm_options->external, opts, line);
    njs_vm_destroy(vm);
    vm = NULL;

    return NXT_OK;
}

static njs_vm_t *
njs_create_vm(njs_opts_t *opts, njs_vm_opt_t *vm_options)
{
    u_char      *p, *start;
    njs_vm_t    *vm;
    nxt_int_t   ret;
    nxt_str_t   path;
    nxt_uint_t  i;

    vm = njs_vm_create(vm_options);
    if (vm == NULL) {
        nxt_error("failed to create vm\n");
        return NULL;
    }

    if (njs_externals_init(vm, vm_options->external) != NXT_OK) {
        nxt_error("failed to add external protos\n");
        return NULL;
    }

    for (i = 0; i < opts->n_paths; i++) {
        path.start = (u_char *) opts->paths[i];
        path.length = nxt_strlen(opts->paths[i]);

        ret = njs_vm_add_path(vm, &path);
        if (ret != NXT_OK) {
            nxt_error("failed to add path\n");
            return NULL;
        }
    }

    start = (u_char *) getenv("NJS_PATH");
    if (start == NULL) {
        return vm;
    }

    for ( ;; ) {
        p = nxt_strchr(start, ':');

        path.start = start;
        path.length = (p != NULL) ? (size_t) (p - start) : nxt_strlen(start);

        ret = njs_vm_add_path(vm, &path);
        if (ret != NXT_OK) {
            nxt_error("failed to add path\n");
            return NULL;
        }

        if (p == NULL) {
            break;
        }

        start = p + 1;
    }

    return vm;
}


static nxt_int_t
njs_process_events(njs_console_t *console, njs_opts_t *opts)
{
    njs_ev_t          *ev;
    nxt_queue_t       *events;
    nxt_queue_link_t  *link;

    events = &console->posted_events;

    for ( ;; ) {
        link = nxt_queue_first(events);

        if (link == nxt_queue_tail(events)) {
            break;
        }

        ev = nxt_queue_link_data(link, njs_ev_t, link);

        nxt_queue_remove(&ev->link);
        ev->link.prev = NULL;
        ev->link.next = NULL;

        njs_vm_post_event(console->vm, ev->vm_event, NULL, 0);
    }

    return NXT_OK;
}


static nxt_int_t
njs_process_script(njs_console_t *console, njs_opts_t *opts,
    const nxt_str_t *script)
{
    u_char     *start;
    njs_vm_t   *vm;
    nxt_int_t  ret;

    vm = console->vm;
    start = script->start;

    ret = njs_vm_compile(vm, &start, start + script->length);

    if (ret == NXT_OK) {
        if (opts->disassemble) {
            njs_disassembler(vm);
            nxt_printf("\n");
        }

        ret = njs_vm_start(vm);
    }

    for ( ;; ) {
        if (!njs_vm_pending(vm)) {
            break;
        }

        ret = njs_process_events(console, opts);
        if (nxt_slow_path(ret != NXT_OK)) {
            nxt_error("njs_process_events() failed\n");
            ret = NJS_ERROR;
            break;
        }

        if (njs_vm_waiting(vm) && !njs_vm_posted(vm)) {
            /*TODO: async events. */

            nxt_error("njs_process_script(): async events unsupported\n");
            ret = NJS_ERROR;
            break;
        }

        ret = njs_vm_run(vm);
    }

    return ret;
}


static njs_ret_t
njs_ext_console_log(njs_vm_t *vm, njs_value_t *args, nxt_uint_t nargs,
    njs_index_t unused)
{
    nxt_str_t   msg;
    nxt_uint_t  n;

    n = 1;

    while (n < nargs) {
        if (njs_vm_value_dump(vm, &msg, njs_argument(args, n), 1, 0)
            == NJS_ERROR)
        {
            return NJS_ERROR;
        }

        nxt_printf("%s", (n != 1) ? " " : "");
        nxt_print(msg.start, msg.length);

        n++;
    }

    if (nargs > 1) {
        nxt_printf("\n");
    }

    vm->retval = njs_value_undefined;

    return NJS_OK;
}


static njs_ret_t
njs_ext_console_dump(njs_vm_t *vm, njs_value_t *args, nxt_uint_t nargs,
    njs_index_t unused)
{
    nxt_str_t   msg;
    nxt_uint_t  n;

    n = 1;

    while (n < nargs) {
        if (njs_vm_value_dump(vm, &msg, njs_argument(args, n), 1, 1)
            == NJS_ERROR)
        {
            return NJS_ERROR;
        }

        nxt_printf("%s", (n != 1) ? " " : "");
        nxt_print(msg.start, msg.length);

        n++;
    }

    if (nargs > 1) {
        nxt_printf("\n");
    }

    vm->retval = njs_value_undefined;

    return NJS_OK;
}


static njs_ret_t
njs_ext_console_help(njs_vm_t *vm, njs_value_t *args, nxt_uint_t nargs,
    njs_index_t unused)
{
    const njs_object_init_t  *obj, **objpp;

    nxt_printf("VM built-in objects:\n");

    for (objpp = njs_constructor_init; *objpp != NULL; objpp++) {
        obj = *objpp;

        nxt_printf("  %V\n", &obj->name);
    }

    for (objpp = njs_object_init; *objpp != NULL; objpp++) {
        obj = *objpp;

        nxt_printf("  %V\n", &obj->name);
    }

    nxt_printf("\nEmbedded objects:\n");
    nxt_printf("  console\n");

    nxt_printf("\n");

    vm->retval = njs_value_undefined;

    return NJS_OK;
}


static njs_ret_t
njs_ext_console_time(njs_vm_t *vm, njs_value_t *args, nxt_uint_t nargs,
    njs_index_t unused)
{
    njs_console_t  *console;

    if (!njs_value_is_undefined(njs_arg(args, nargs, 1))) {
        njs_vm_error(vm, "labels not implemented");
        return NJS_ERROR;
    }

    console = njs_vm_external(vm, njs_arg(args, nargs, 0));
    if (nxt_slow_path(console == NULL)) {
        return NJS_ERROR;
    }

    console->time = nxt_time();

    vm->retval = njs_value_undefined;

    return NJS_OK;
}


static njs_ret_t
njs_ext_console_time_end(njs_vm_t *vm, njs_value_t *args, nxt_uint_t nargs,
    njs_index_t unused)
{
    uint64_t       ns, ms;
    njs_console_t  *console;

    ns = nxt_time();

    if (!njs_value_is_undefined(njs_arg(args, nargs, 1))) {
        njs_vm_error(vm, "labels not implemented");
        return NJS_ERROR;
    }

    console = njs_vm_external(vm, njs_arg(args, nargs, 0));
    if (nxt_slow_path(console == NULL)) {
        return NJS_ERROR;
    }

    if (nxt_fast_path(console->time != UINT64_MAX)) {

        ns = ns - console->time;

        ms = ns / 1000000;
        ns = ns % 1000000;

        nxt_printf("default: %uL.%06uLms\n", ms, ns);

        console->time = UINT64_MAX;

    } else {
        nxt_printf("Timer \"default\" doesn’t exist.\n");
    }

    vm->retval = njs_value_undefined;

    return NJS_OK;
}


static njs_host_event_t
njs_console_set_timer(njs_external_ptr_t external, uint64_t delay,
    njs_vm_event_t vm_event)
{
    njs_ev_t            *ev;
    njs_vm_t            *vm;
    nxt_int_t           ret;
    njs_console_t       *console;
    nxt_lvlhsh_query_t  lhq;

    if (delay != 0) {
        nxt_error("njs_console_set_timer(): async timers unsupported\n");
        return NULL;
    }

    console = external;
    vm = console->vm;

    ev = nxt_mp_alloc(vm->mem_pool, sizeof(njs_ev_t));
    if (nxt_slow_path(ev == NULL)) {
        return NULL;
    }

    ev->vm_event = vm_event;

    lhq.key.start = (u_char *) &ev->vm_event;
    lhq.key.length = sizeof(njs_vm_event_t);
    lhq.key_hash = nxt_djb_hash(lhq.key.start, lhq.key.length);

    lhq.replace = 0;
    lhq.value = ev;
    lhq.proto = &lvlhsh_proto;
    lhq.pool = vm->mem_pool;

    ret = nxt_lvlhsh_insert(&console->events, &lhq);
    if (nxt_slow_path(ret != NXT_OK)) {
        return NULL;
    }

    nxt_queue_insert_tail(&console->posted_events, &ev->link);

    return (njs_host_event_t) ev;
}


static void
njs_console_clear_timer(njs_external_ptr_t external, njs_host_event_t event)
{
    njs_vm_t            *vm;
    njs_ev_t            *ev;
    nxt_int_t           ret;
    njs_console_t       *console;
    nxt_lvlhsh_query_t  lhq;

    ev = event;
    console = external;
    vm = console->vm;

    lhq.key.start = (u_char *) &ev->vm_event;
    lhq.key.length = sizeof(njs_vm_event_t);
    lhq.key_hash = nxt_djb_hash(lhq.key.start, lhq.key.length);

    lhq.proto = &lvlhsh_proto;
    lhq.pool = vm->mem_pool;

    if (ev->link.prev != NULL) {
        nxt_queue_remove(&ev->link);
    }

    ret = nxt_lvlhsh_delete(&console->events, &lhq);
    if (ret != NXT_OK) {
        nxt_error("nxt_lvlhsh_delete() failed\n");
    }

    nxt_mp_free(vm->mem_pool, ev);
}


static nxt_int_t
lvlhsh_key_test(nxt_lvlhsh_query_t *lhq, void *data)
{
    njs_ev_t  *ev;

    ev = data;

    if (memcmp(&ev->vm_event, lhq->key.start, sizeof(njs_vm_event_t)) == 0) {
        return NXT_OK;
    }

    return NXT_DECLINED;
}


static void *
lvlhsh_pool_alloc(void *pool, size_t size, nxt_uint_t nalloc)
{
    return nxt_mp_align(pool, size, size);
}


static void
lvlhsh_pool_free(void *pool, void *p, size_t size)
{
    nxt_mp_free(pool, p);
}


int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;

  char* input = malloc(size + 1);
  memcpy(input, data, size);
  input[size] = 0;
  nxt_str_t line = {size, input};

  njs_vm_t      *vm;
  nxt_int_t     ret;
  njs_opts_t    opts;
  nxt_str_t     command;
  njs_vm_opt_t  vm_options;

  nxt_memzero(&opts, sizeof(njs_opts_t));
  opts.interactive = 1;

  nxt_memzero(&vm_options, sizeof(njs_vm_opt_t));

  vm_options.init = !opts.interactive;
  vm_options.accumulative = opts.interactive;
  vm_options.backtrace = 1;
  vm_options.quiet = opts.quiet;
  vm_options.sandbox = opts.sandbox;
  vm_options.module = opts.module;

  vm_options.ops = &njs_console_ops;
  vm_options.external = &njs_console;

  ret = njs_interactive_shell(&opts, &vm_options, &line);
  free(input);

  if (ret != NXT_OK)
    return 0;

  return 0;
}
