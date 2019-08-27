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

#include <njs_main.h>
#include <njs_value.h>

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
    njs_array_t             *completions;
    njs_array_t             *suffix_completions;
    njs_lvlhsh_each_t       lhe;

    enum {
       NJS_COMPLETION_VAR = 0,
       NJS_COMPLETION_SUFFIX,
       NJS_COMPLETION_GLOBAL
    }                       phase;
} njs_completion_t;


typedef struct {
    njs_vm_event_t          vm_event;
    njs_queue_link_t        link;
} njs_ev_t;


typedef struct {
    njs_vm_t                *vm;

    njs_lvlhsh_t            events;  /* njs_ev_t * */
    njs_queue_t             posted_events;

    uint64_t                time;

    njs_completion_t        completion;
} njs_console_t;


static njs_int_t njs_console_init(njs_vm_t *vm, njs_console_t *console);
static njs_int_t njs_externals_init(njs_vm_t *vm, njs_console_t *console);
static njs_int_t njs_interactive_shell(njs_opts_t *opts,
    njs_vm_opt_t *vm_options, njs_str_t *line);
static njs_vm_t *njs_create_vm(njs_opts_t *opts, njs_vm_opt_t *vm_options);
static njs_int_t njs_process_script(njs_console_t *console, njs_opts_t *opts,
    const njs_str_t *script);

static njs_int_t njs_ext_console_log(njs_vm_t *vm, njs_value_t *args,
    njs_uint_t nargs, njs_index_t unused);
static njs_int_t njs_ext_console_dump(njs_vm_t *vm, njs_value_t *args,
    njs_uint_t nargs, njs_index_t unused);
static njs_int_t njs_ext_console_help(njs_vm_t *vm, njs_value_t *args,
    njs_uint_t nargs, njs_index_t unused);
static njs_int_t njs_ext_console_time(njs_vm_t *vm, njs_value_t *args,
    njs_uint_t nargs, njs_index_t unused);
static njs_int_t njs_ext_console_time_end(njs_vm_t *vm, njs_value_t *args,
    njs_uint_t nargs, njs_index_t unused);

static njs_host_event_t njs_console_set_timer(njs_external_ptr_t external,
    uint64_t delay, njs_vm_event_t vm_event);
static void njs_console_clear_timer(njs_external_ptr_t external,
    njs_host_event_t event);

static njs_int_t lvlhsh_key_test(njs_lvlhsh_query_t *lhq, void *data);
static void *lvlhsh_pool_alloc(void *pool, size_t size, njs_uint_t nalloc);
static void lvlhsh_pool_free(void *pool, void *p, size_t size);


static njs_external_t  njs_ext_console[] = {

    { njs_str("log"),
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

    { njs_str("dump"),
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

    { njs_str("help"),
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

    { njs_str("time"),
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

    { njs_str("timeEnd"),
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

    { njs_str("console"),
      NJS_EXTERN_OBJECT,
      njs_ext_console,
      njs_nitems(njs_ext_console),
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL,
      0 },
};


static const njs_lvlhsh_proto_t  lvlhsh_proto  njs_aligned(64) = {
    NJS_LVLHSH_LARGE_SLAB,
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


static njs_int_t
njs_console_init(njs_vm_t *vm, njs_console_t *console)
{
    console->vm = vm;

    njs_lvlhsh_init(&console->events);
    njs_queue_init(&console->posted_events);

    console->time = UINT64_MAX;

    console->completion.completions = njs_vm_completions(vm, NULL);
    if (console->completion.completions == NULL) {
        return NJS_ERROR;
    }

    return NJS_OK;
}


static njs_int_t
njs_externals_init(njs_vm_t *vm, njs_console_t *console)
{
    njs_uint_t          ret;
    njs_value_t         *value;
    const njs_extern_t  *proto;

    static const njs_str_t name = njs_str("console");

    proto = njs_vm_external_prototype(vm, &njs_externals[0]);
    if (proto == NULL) {
        njs_stderror("failed to add console proto\n");
        return NJS_ERROR;
    }

    value = njs_mp_zalloc(vm->mem_pool, sizeof(njs_opaque_value_t));
    if (value == NULL) {
        return NJS_ERROR;
    }

    ret = njs_vm_external_create(vm, value, proto, console);
    if (ret != NJS_OK) {
        return NJS_ERROR;
    }

    ret = njs_vm_external_bind(vm, &name, value);
    if (ret != NJS_OK) {
        return NJS_ERROR;
    }

    ret = njs_console_init(vm, console);
    if (ret != NJS_OK) {
        return NJS_ERROR;
    }

    return NJS_OK;
}

static njs_int_t
njs_interactive_shell(njs_opts_t *opts, njs_vm_opt_t *vm_options, njs_str_t *line)
{
    njs_vm_t   *vm;

    vm = njs_create_vm(opts, vm_options);
    if (vm == NULL) {
        return NJS_ERROR;
    }

    njs_process_script(vm_options->external, opts, line);
    njs_vm_destroy(vm);
    vm = NULL;

    return NJS_OK;
}

static njs_vm_t *
njs_create_vm(njs_opts_t *opts, njs_vm_opt_t *vm_options)
{
    u_char      *p, *start;
    njs_vm_t    *vm;
    njs_int_t   ret;
    njs_str_t   path;
    njs_uint_t  i;

    vm = njs_vm_create(vm_options);
    if (vm == NULL) {
        njs_stderror("failed to create vm\n");
        return NULL;
    }

    if (njs_externals_init(vm, vm_options->external) != NJS_OK) {
        njs_stderror("failed to add external protos\n");
        return NULL;
    }

    for (i = 0; i < opts->n_paths; i++) {
        path.start = (u_char *) opts->paths[i];
        path.length = njs_strlen(opts->paths[i]);

        ret = njs_vm_add_path(vm, &path);
        if (ret != NJS_OK) {
            njs_stderror("failed to add path\n");
            return NULL;
        }
    }

    start = (u_char *) getenv("NJS_PATH");
    if (start == NULL) {
        return vm;
    }

    for ( ;; ) {
        p = njs_strchr(start, ':');

        path.start = start;
        path.length = (p != NULL) ? (size_t) (p - start) : njs_strlen(start);

        ret = njs_vm_add_path(vm, &path);
        if (ret != NJS_OK) {
            njs_stderror("failed to add path\n");
            return NULL;
        }

        if (p == NULL) {
            break;
        }

        start = p + 1;
    }

    return vm;
}


static njs_int_t
njs_process_events(njs_console_t *console, njs_opts_t *opts)
{
    njs_ev_t          *ev;
    njs_queue_t       *events;
    njs_queue_link_t  *link;

    events = &console->posted_events;

    for ( ;; ) {
        link = njs_queue_first(events);

        if (link == njs_queue_tail(events)) {
            break;
        }

        ev = njs_queue_link_data(link, njs_ev_t, link);

        njs_queue_remove(&ev->link);
        ev->link.prev = NULL;
        ev->link.next = NULL;

        njs_vm_post_event(console->vm, ev->vm_event, NULL, 0);
    }

    return NJS_OK;
}


static njs_int_t
njs_process_script(njs_console_t *console, njs_opts_t *opts,
    const njs_str_t *script)
{
    u_char     *start;
    njs_vm_t   *vm;
    njs_int_t  ret;

    vm = console->vm;
    start = script->start;

    ret = njs_vm_compile(vm, &start, start + script->length);

    if (ret == NJS_OK) {
        if (opts->disassemble) {
            njs_disassembler(vm);
            njs_printf("\n");
        }

        ret = njs_vm_start(vm);
    }

    for ( ;; ) {
        if (!njs_vm_pending(vm)) {
            break;
        }

        ret = njs_process_events(console, opts);
        if (njs_slow_path(ret != NJS_OK)) {
            njs_stderror("njs_process_events() failed\n");
            ret = NJS_ERROR;
            break;
        }

        if (njs_vm_waiting(vm) && !njs_vm_posted(vm)) {
            /*TODO: async events. */

            njs_stderror("njs_process_script(): async events unsupported\n");
            ret = NJS_ERROR;
            break;
        }

        ret = njs_vm_run(vm);
    }

    return ret;
}


static njs_int_t
njs_ext_console_log(njs_vm_t *vm, njs_value_t *args, njs_uint_t nargs,
    njs_index_t unused)
{
    njs_str_t   msg;
    njs_uint_t  n;

    n = 1;

    while (n < nargs) {
        if (njs_vm_value_dump(vm, &msg, njs_argument(args, n), 1, 0)
            == NJS_ERROR)
        {
            return NJS_ERROR;
        }

        njs_printf("%s", (n != 1) ? " " : "");
        njs_print(msg.start, msg.length);

        n++;
    }

    if (nargs > 1) {
        njs_printf("\n");
    }

    vm->retval = njs_value_undefined;

    return NJS_OK;
}


static njs_int_t
njs_ext_console_dump(njs_vm_t *vm, njs_value_t *args, njs_uint_t nargs,
    njs_index_t unused)
{
    njs_str_t   msg;
    njs_uint_t  n;

    n = 1;

    while (n < nargs) {
        if (njs_vm_value_dump(vm, &msg, njs_argument(args, n), 1, 1)
            == NJS_ERROR)
        {
            return NJS_ERROR;
        }

        njs_printf("%s", (n != 1) ? " " : "");
        njs_print(msg.start, msg.length);

        n++;
    }

    if (nargs > 1) {
        njs_printf("\n");
    }

    vm->retval = njs_value_undefined;

    return NJS_OK;
}


static njs_int_t
njs_ext_console_help(njs_vm_t *vm, njs_value_t *args, njs_uint_t nargs,
    njs_index_t unused)
{
    const njs_object_init_t  *obj, **objpp;

    njs_printf("VM built-in objects:\n");

    for (objpp = njs_constructor_init; *objpp != NULL; objpp++) {
        obj = *objpp;

        njs_printf("  %V\n", &obj->name);
    }

    for (objpp = njs_object_init; *objpp != NULL; objpp++) {
        obj = *objpp;

        njs_printf("  %V\n", &obj->name);
    }

    njs_printf("\nEmbedded objects:\n");
    njs_printf("  console\n");

    njs_printf("\n");

    vm->retval = njs_value_undefined;

    return NJS_OK;
}


static njs_int_t
njs_ext_console_time(njs_vm_t *vm, njs_value_t *args, njs_uint_t nargs,
    njs_index_t unused)
{
    njs_console_t  *console;

    if (!njs_value_is_undefined(njs_arg(args, nargs, 1))) {
        njs_vm_error(vm, "labels not implemented");
        return NJS_ERROR;
    }

    console = njs_vm_external(vm, njs_arg(args, nargs, 0));
    if (njs_slow_path(console == NULL)) {
        return NJS_ERROR;
    }

    console->time = njs_time();

    vm->retval = njs_value_undefined;

    return NJS_OK;
}


static njs_int_t
njs_ext_console_time_end(njs_vm_t *vm, njs_value_t *args, njs_uint_t nargs,
    njs_index_t unused)
{
    uint64_t       ns, ms;
    njs_console_t  *console;

    ns = njs_time();

    if (!njs_value_is_undefined(njs_arg(args, nargs, 1))) {
        njs_vm_error(vm, "labels not implemented");
        return NJS_ERROR;
    }

    console = njs_vm_external(vm, njs_arg(args, nargs, 0));
    if (njs_slow_path(console == NULL)) {
        return NJS_ERROR;
    }

    if (njs_fast_path(console->time != UINT64_MAX)) {

        ns = ns - console->time;

        ms = ns / 1000000;
        ns = ns % 1000000;

        njs_printf("default: %uL.%06uLms\n", ms, ns);

        console->time = UINT64_MAX;

    } else {
        njs_printf("Timer \"default\" doesn’t exist.\n");
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
    njs_int_t           ret;
    njs_console_t       *console;
    njs_lvlhsh_query_t  lhq;

    if (delay != 0) {
        njs_stderror("njs_console_set_timer(): async timers unsupported\n");
        return NULL;
    }

    console = external;
    vm = console->vm;

    ev = njs_mp_alloc(vm->mem_pool, sizeof(njs_ev_t));
    if (njs_slow_path(ev == NULL)) {
        return NULL;
    }

    ev->vm_event = vm_event;

    lhq.key.start = (u_char *) &ev->vm_event;
    lhq.key.length = sizeof(njs_vm_event_t);
    lhq.key_hash = njs_djb_hash(lhq.key.start, lhq.key.length);

    lhq.replace = 0;
    lhq.value = ev;
    lhq.proto = &lvlhsh_proto;
    lhq.pool = vm->mem_pool;

    ret = njs_lvlhsh_insert(&console->events, &lhq);
    if (njs_slow_path(ret != NJS_OK)) {
        return NULL;
    }

    njs_queue_insert_tail(&console->posted_events, &ev->link);

    return (njs_host_event_t) ev;
}


static void
njs_console_clear_timer(njs_external_ptr_t external, njs_host_event_t event)
{
    njs_vm_t            *vm;
    njs_ev_t            *ev;
    njs_int_t           ret;
    njs_console_t       *console;
    njs_lvlhsh_query_t  lhq;

    ev = event;
    console = external;
    vm = console->vm;

    lhq.key.start = (u_char *) &ev->vm_event;
    lhq.key.length = sizeof(njs_vm_event_t);
    lhq.key_hash = njs_djb_hash(lhq.key.start, lhq.key.length);

    lhq.proto = &lvlhsh_proto;
    lhq.pool = vm->mem_pool;

    if (ev->link.prev != NULL) {
        njs_queue_remove(&ev->link);
    }

    ret = njs_lvlhsh_delete(&console->events, &lhq);
    if (ret != NJS_OK) {
        njs_stderror("njs_lvlhsh_delete() failed\n");
    }

    njs_mp_free(vm->mem_pool, ev);
}


static njs_int_t
lvlhsh_key_test(njs_lvlhsh_query_t *lhq, void *data)
{
    njs_ev_t  *ev;

    ev = data;

    if (memcmp(&ev->vm_event, lhq->key.start, sizeof(njs_vm_event_t)) == 0) {
        return NJS_OK;
    }

    return NJS_DECLINED;
}


static void *
lvlhsh_pool_alloc(void *pool, size_t size, njs_uint_t nalloc)
{
    return njs_mp_align(pool, size, size);
}


static void
lvlhsh_pool_free(void *pool, void *p, size_t size)
{
    njs_mp_free(pool, p);
}


int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) return 0;

  char* input = malloc(size);
  memcpy(input, data, size);
  njs_str_t line = {size, input};

  njs_vm_t      *vm;
  njs_int_t     ret;
  njs_opts_t    opts;
  njs_str_t     command;
  njs_vm_opt_t  vm_options;

  njs_memzero(&opts, sizeof(njs_opts_t));
  opts.interactive = 1;

  njs_memzero(&vm_options, sizeof(njs_vm_opt_t));

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

  if (ret != NJS_OK)
    return 0;

  return 0;
}
