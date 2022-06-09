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

#include "common/jsonapi.h"
#include "mb/pg_wchar.h"
#include "utils/memutils.h"
#include "utils/memdebug.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	FuzzerInitialize("json_db", argv);
	return 0;
}

/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	sigjmp_buf local_sigjmp_buf;
	char *buffer;
	JsonSemAction sem;
	JsonLexContext *lex;

	buffer = (char *) calloc(size+1, sizeof(char));
	memcpy(buffer, data, size);

	MemoryContextInit();
	set_stack_base();
	sem = nullSemAction;
	lex = makeJsonLexContextCstringLen(buffer, size+1, PG_UTF8, true);

	if(!sigsetjmp(local_sigjmp_buf,0)){
		error_context_stack = NULL;
		PG_exception_stack = &local_sigjmp_buf;
		pg_parse_json(lex, &sem);
	}
	free(buffer);
	FlushErrorState();
	MemoryContextReset(TopMemoryContext);
	TopMemoryContext->ident = NULL;
	TopMemoryContext->methods->delete_context(TopMemoryContext);
	VALGRIND_DESTROY_MEMPOOL(TopMemoryContext);
	return 0;
}
