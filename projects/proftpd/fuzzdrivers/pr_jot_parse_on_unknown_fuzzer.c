#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "bindings.h"
#include "class.h"
#include "conf.h"
#include "configdb.h"
#include "ctrls.h"
#include "dirtree.h"
#include "error.h"
#include "expr.h"
#include "fsio.h"
#include "inet.h"
#include "jot.h"
#include "json.h"
#include "memcache.h"
#include "mod_ctrls.h"
#include "netaddr.h"
#include "openbsd-blowfish.h"
#include "os.h"
#include "pr-syslog.h"
#include "proftpd.h"
#include "redis.h"
#include "sets.h"
#include "signals.h"
#include "table.h"
#include "version.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    pool *p;
    pr_jot_ctx_t *jot_ctx;
    char *text;
    int ret;

    p = make_sub_pool(NULL);
    jot_ctx = (pr_jot_ctx_t *)pcalloc(p, sizeof(pr_jot_ctx_t));
    text = (char *)pcalloc(p, Size + 1);
    memcpy(text, Data, Size);

    ret = pr_jot_parse_on_unknown(p, jot_ctx, text, Size);
    destroy_pool(p);
    return ret;
}
