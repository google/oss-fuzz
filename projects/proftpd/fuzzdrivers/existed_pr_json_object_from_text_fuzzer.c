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
    pr_json_object_t *obj;
    char *text;

    if (Size < 2) return 0;

    p = make_sub_pool(permanent_pool);
    pr_pool_tag(p, "fuzz pool");

    text = pcalloc(p, Size+1);
    memcpy(text, Data, Size);

    obj = pr_json_object_from_text(p, text);
    destroy_pool(p);
    return 0;
}
