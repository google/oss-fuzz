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

#include "postgres.h"
#include "parser/gramparse.h"
#include "parser/parser.h"
#include "parser/analyze.h"
#include "utils/memutils.h"
#include "utils/memdebug.h"
#include "rewrite/rewriteHandler.h"
#include "optimizer/optimizer.h"
#include "utils/snapmgr.h"
#include "nodes/params.h"
#include "nodes/plannodes.h"
#include "nodes/pg_list.h"

const char *progname = "progname";

List *plan_queries(List *querytrees, const char *query_string, int cursorOptions,
                 ParamListInfo boundParams) {
     List       *stmt_list = NIL;
     ListCell   *query_list;
 
     foreach(query_list, querytrees) {
         Query      *query = lfirst_node(Query, query_list);
         PlannedStmt *stmt;

		 if (query->commandType == CMD_UTILITY) {
             stmt = makeNode(PlannedStmt);
             stmt->commandType = CMD_UTILITY;
             stmt->canSetTag = query->canSetTag;
             stmt->utilityStmt = query->utilityStmt;
             stmt->stmt_location = query->stmt_location;
             stmt->stmt_len = query->stmt_len;
         } else {
			 stmt = planner(query, query_string, cursorOptions,
							boundParams);
		 }
 
		 stmt_list = lappend(stmt_list, stmt);
     }
 
     return stmt_list;
 }


/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	char* query_string;
	sigjmp_buf local_sigjmp_buf;
	List       *parsetree_list;
	ListCell   *parsetree_item;

   	MemoryContextInit();
 	query_string = (char*) calloc( (size+1), sizeof(char) );
	memcpy(query_string, data, size);
	MessageContext = AllocSetContextCreate(TopMemoryContext,
                                            "MessageContext",
                                            ALLOCSET_DEFAULT_SIZES);

	if(!sigsetjmp(local_sigjmp_buf,0)){
		MemoryContext oldcontext;

		error_context_stack = NULL;
		PG_exception_stack = &local_sigjmp_buf;

		oldcontext = MemoryContextSwitchTo(MessageContext);
		parsetree_list = raw_parser(query_string);
		MemoryContextSwitchTo(oldcontext);
		
		foreach(parsetree_item, parsetree_list) {
			RawStmt    *parsetree = lfirst_node(RawStmt, parsetree_item);
			MemoryContext per_parsetree_context = NULL;
			List       *querytree_list;
			Query *query;

			if (analyze_requires_snapshot(parsetree)){
				PushActiveSnapshot(GetTransactionSnapshot());
			}
			if (lnext(parsetree_list, parsetree_item) != NULL){
				per_parsetree_context =
					AllocSetContextCreate(MessageContext,
										  "per-parsetree message context",
										  ALLOCSET_DEFAULT_SIZES);
				MemoryContextSwitchTo(per_parsetree_context);
			} else {
				MemoryContextSwitchTo(MessageContext);
			}
			query = parse_analyze(parsetree, query_string, NULL, 0, NULL);
			if (query->commandType == CMD_UTILITY) {
				querytree_list = list_make1(query);
			} else {
				querytree_list = QueryRewrite(query);
			}
 			plan_queries(querytree_list, query_string, CURSOR_OPT_PARALLEL_OK, NULL);
 			if (per_parsetree_context){
				MemoryContextDelete(per_parsetree_context);
			}
		}
	}
	
	free(query_string);
	FlushErrorState();
	MemoryContextReset(TopMemoryContext);
	TopMemoryContext->ident = NULL;
	TopMemoryContext->methods->delete_context(TopMemoryContext);
	VALGRIND_DESTROY_MEMPOOL(TopMemoryContext);
	return 0;
}
