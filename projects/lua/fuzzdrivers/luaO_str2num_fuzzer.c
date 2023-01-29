#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lapi.h"
#include "lauxlib.h"
#include "lcode.h"
#include "lctype.h"
#include "ldebug.h"
#include "ldo.h"
#include "lfunc.h"
#include "lgc.h"
#include "llex.h"
#include "llimits.h"
#include "lmem.h"
#include "lobject.h"
#include "lopcodes.h"
#include "lopnames.h"
#include "lparser.h"
#include "lprefix.h"
#include "lstate.h"
#include "lstring.h"
#include "ltable.h"
#include "ltests.h"
#include "ltm.h"
#include "lua.h"
#include "luaconf.h"
#include "lualib.h"
#include "lundump.h"
#include "lvm.h"
#include "lzio.h"
#include "lobject.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *s = (char *)malloc(Size + 1);
    memcpy(s, Data, Size);
    s[Size] = '\0';
    TValue o;
    luaO_str2num(s, &o);
    free(s);
    return 0;
}
