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
    pool *acl_pool = make_sub_pool(NULL);
    char *acl_text = (char *)malloc(Size + 1);
    memcpy(acl_text, Data, Size);
    acl_text[Size] = 0;
    pr_ctrls_parse_acl(acl_pool, acl_text);
    free(acl_text);
    destroy_pool(acl_pool);
    return 0;
}
