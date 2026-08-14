/*
 * Copyright 2026 Google LLC
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

/*
 * SQL parser fuzzer for TDengine 3.x.
 *
 * This fuzzer exercises the SQL syntax parsing layer (qParseSqlSyntax),
 * which tokenises and builds an AST from untrusted SQL input without
 * requiring a running TDengine server or catalog.  It is the first
 * layer of SQL processing and is therefore the highest-risk entry
 * point for parsing bugs (buffer overflows, OOB reads, infinite loops,
 * assertion failures, etc.).
 */

#include <stdint.h>
#include <string.h>

/* Include the OS abstraction first so TDengine memory wrappers are defined
 * before any other TDengine headers redefine malloc/free. */
#include "os.h"
#include "parser.h"
#include "catalog.h"
#include "querynodes.h"

/* One-time initialisation flag. */
static int g_init = 0;

/* Error message buffer reused every call. */
#define MSG_BUF_LEN 4096
static char g_msgBuf[MSG_BUF_LEN];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Initialise keyword table once. */
  if (!g_init) {
    qInitKeywordsTable();
    g_init = 1;
  }

  /* Require at least one byte so we always have a null-terminated string. */
  if (size == 0) {
    return 0;
  }

  /* Copy input and null-terminate so that the parser can treat it as a
   * C-string safely.  We deliberately limit to 64 KB to keep the fuzzer
   * fast; real SQL queries are never this long in practice. */
  if (size > 65536) {
    size = 65536;
  }
  /* Use TDengine's memory allocator (direct malloc/free are forbidden). */
  char *sql = (char *)taosMemoryMalloc(size + 1);
  if (!sql) {
    return 0;
  }
  memcpy(sql, data, size);
  sql[size] = '\0';

  /* Prepare a minimal parse context.
   * allocatorId = 0 → use the default (no custom arena allocator).
   * parseOnly is intentionally left false; we set up enough context
   * for syntax-only parsing via qParseSqlSyntax. */
  SParseContext cxt;
  memset(&cxt, 0, sizeof(cxt));
  cxt.acctId        = 1;
  cxt.db            = "fuzz_db";
  cxt.pUser         = "root";
  cxt.isSuperUser   = true;
  cxt.enableSysInfo = true;
  cxt.privInfo      = (uint16_t)0xFFFF;  /* grant all privileges */
  cxt.pSql          = sql;
  cxt.sqlLen        = size;
  cxt.pMsg          = g_msgBuf;
  cxt.msgLen        = MSG_BUF_LEN;
  cxt.svrVer        = "3.0.0.0";
  cxt.allocatorId   = 0;

  SQuery      *pQuery     = NULL;
  SCatalogReq  catalogReq;
  memset(&catalogReq, 0, sizeof(catalogReq));

  /* Parse SQL syntax only – no network/catalog required. */
  (void)qParseSqlSyntax(&cxt, &pQuery, &catalogReq);

  /* Clean up. */
  if (pQuery) {
    qDestroyQuery(pQuery);
  }

  taosMemoryFree(sql);
  return 0;
}
