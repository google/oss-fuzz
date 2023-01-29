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
    int p = 0;
    char *flags_str = (char *)malloc(Size + 1);
    memcpy(flags_str, Data, Size);
    flags_str[Size] = 0;
    pr_filter_parse_flags(&p, flags_str);
    free(flags_str);
    return 0;
}
