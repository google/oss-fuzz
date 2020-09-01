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

#include "access/xlog.h"
#include "access/xact.h"
#include "common/jsonapi.h"
#include "common/username.h"
#include "executor/spi.h"
#include "jit/jit.h"
#include "libpq/libpq.h"
#include "libpq/pqsignal.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "optimizer/optimizer.h"
#include "parser/analyze.h"
#include "parser/parser.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/datetime.h"
#include "utils/memdebug.h"
#include "utils/memutils.h"
#include "utils/portal.h"
#include "utils/snapmgr.h"
#include "utils/timeout.h"

const char *progname = "progname";
static const char *userDoption;
static MemoryContext row_description_context = NULL;
static StringInfoData row_description_buf;
static const char *dbname = NULL;
static const char *username = NULL;
extern char _binary_json_db_tar_gz_start[];
extern char _binary_json_db_tar_gz_end[];

static void fuzzer_exit(){
  if(!username)
    pfree((void *) username);
}


int __attribute__((constructor)) Initialize(void) {
  int argc = 4;
  char *argv[4];
  argv[0] = "tmp_install/usr/local/pgsql/bin/postgres";
  argv[1] = "-D\"/tmp/json_db/data\"";
  argv[2] = "-F";
  argv[3] = "-k\"/tmp/pg_dbfuzz\"";

  FILE * fp; fp = fopen("/tmp/json_db.tar.gz", "w");
  unsigned int tarsize =  (unsigned int)(_binary_json_db_tar_gz_end - _binary_json_db_tar_gz_start);
  fwrite(_binary_json_db_tar_gz_start, 1, tarsize, fp);
  fclose(fp);
  system("tar -xvf /tmp/json_db.tar.gz -C /tmp/");
  
  progname = get_progname(argv[0]);
  MemoryContextInit();

  username = strdup(get_user_name_or_exit(progname));
	 
  InitStandaloneProcess(argv[0]);
  SetProcessingMode(InitProcessing);
  InitializeGUCOptions();
  process_postgres_switches(argc, argv, PGC_POSTMASTER, &dbname);
  dbname = "dbfuzz";

  userDoption = "/tmp/json_db/data";
  SelectConfigFiles(userDoption, progname);

  checkDataDir();
  ChangeToDataDir();
  CreateDataDirLockFile(false);
  LocalProcessControlFile(false);
  InitializeMaxBackends();
		 
  BaseInit();
  InitProcess();
  PG_SETMASK(&UnBlockSig);
  InitPostgres(dbname, InvalidOid, username, InvalidOid, NULL, false);
 
  SetProcessingMode(NormalProcessing);

  BeginReportingGUCOptions();
  process_session_preload_libraries();

  MessageContext = AllocSetContextCreate(TopMemoryContext,
										 "MessageContext",
										 ALLOCSET_DEFAULT_SIZES);
  row_description_context = AllocSetContextCreate(TopMemoryContext,
												  "RowDescriptionContext",
												  ALLOCSET_DEFAULT_SIZES);
  MemoryContextSwitchTo(row_description_context);
  initStringInfo(&row_description_buf);
  MemoryContextSwitchTo(TopMemoryContext);

  PgStartTime = GetCurrentTimestamp();
  whereToSendOutput = DestNone;
  Log_destination = 0;
  atexit(fuzzer_exit);
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
