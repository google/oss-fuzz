// Copyright 2020 Google LLC
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
//
///////////////////////////////////////////////////////////////////////////////

#include "postgres.h"

#include "access/xlog.h"
#include "access/xact.h"
#include "common/username.h"
#include "executor/spi.h"
#include "jit/jit.h"
#include "libpq/libpq.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "optimizer/optimizer.h"
#include "parser/analyze.h"
#include "parser/parser.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/datetime.h"
#include "utils/memutils.h"
#include "utils/portal.h"
#include "utils/snapmgr.h"
#include "utils/timeout.h"

static void exec_simple_query(const char *query_string) {
  MemoryContext oldcontext;
  List *parsetree_list;
  ListCell *parsetree_item;

  oldcontext = MemoryContextSwitchTo(MessageContext);
  parsetree_list = raw_parser(query_string, RAW_PARSE_TYPE_NAME);
  MemoryContextSwitchTo(oldcontext);

  foreach (parsetree_item, parsetree_list) {
    RawStmt *parsetree = lfirst_node(RawStmt, parsetree_item);
    MemoryContext per_parsetree_context = NULL;
    List *querytree_list;

    if (lnext(parsetree_list, parsetree_item) != NULL) {
      per_parsetree_context =
          AllocSetContextCreate(MessageContext, "per-parsetree message context", ALLOCSET_DEFAULT_SIZES);
      oldcontext = MemoryContextSwitchTo(per_parsetree_context);
    } else {
      oldcontext = MemoryContextSwitchTo(MessageContext);
    }

    querytree_list = pg_analyze_and_rewrite_fixedparams(parsetree, query_string, NULL, 0, NULL);
    pg_plan_queries(querytree_list, query_string, CURSOR_OPT_PARALLEL_OK, NULL);

    if (per_parsetree_context) {
      MemoryContextDelete(per_parsetree_context);
    } else {
      MemoryContextSwitchTo(oldcontext);
    }
  }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  MemoryContextInit();
  InitializeGUCOptions();
  InitializeMaxBackends();

  MessageContext = AllocSetContextCreate(TopMemoryContext,
                                         "MessageContext",
                                         ALLOCSET_DEFAULT_SIZES);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0;

  sigjmp_buf local_sigjmp_buf;
  char *query_string = (char *) calloc(size + 1, sizeof(char));
  memcpy(query_string, data, size);

  if (!sigsetjmp(local_sigjmp_buf, 0)) {
    PG_exception_stack = &local_sigjmp_buf;
    error_context_stack = NULL;
    set_stack_base();

    disable_all_timeouts(false);
    QueryCancelPending = false;
    pq_comm_reset();
    EmitErrorReport();
    jit_reset_after_error();

    MemoryContextSwitchTo(TopMemoryContext);
    FlushErrorState();
    MemoryContextSwitchTo(MessageContext);
    MemoryContextReset(MessageContext);
    SetCurrentStatementStartTimestamp();

    exec_simple_query(query_string);
  }

  free(query_string);
  return 0;
}
