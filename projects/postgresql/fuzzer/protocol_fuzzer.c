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
#include "common/ip.h"
#include "common/username.h"
#include "executor/spi.h"
#include "jit/jit.h"
#include "libpq/auth.h"
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
#include "utils/memdebug.h"
#include "utils/pidfile.h"
#include "utils/portal.h"
#include "utils/snapmgr.h"
#include "utils/ps_status.h"
#include "utils/timeout.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>

const char *progname = "progname";
static sigjmp_buf postgre_exit;
static bool postgre_started;
static char *buffer;
static size_t buffersize;
static char *bufferpointer;
static char *av[6];

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	char *exe_path = (*argv)[0];
	//dirname() can modify its argument
	char *exe_path_copy = strdup(exe_path);
	char *dir = dirname(exe_path_copy);
	chdir(dir);
	free(exe_path_copy);
	
	av[0] = "tmp_install/usr/local/pgsql/bin/postgres";
	av[1] = "--single";
	av[2] = "-D/tmp/protocol_db/data";
	av[3] = "-F";
	av[4] = "-k\"/tmp\"";
	av[5] = NULL;

	system("rm -rf /tmp/protocol_db; mkdir /tmp/protocol_db; cp -r data /tmp/protocol_db");
	system("cp -r tmp_install /tmp/");

	MemoryContextInit();
	if(!sigsetjmp(postgre_exit, 0)){
		postgre_started = true;
		PostgresSingleUserMain(5, av, "fuzzuser");
	}
	pq_endmsgread();
	return 0;
}

void __wrap_exit(int status){
	if(postgre_started)
		siglongjmp(postgre_exit, 1);
	else
		__real_exit(status);
}

int __wrap_pq_getbyte(void){
	if(!buffersize) return EOF;
	unsigned char cur = buffer[0];
	bufferpointer++; buffersize--;
	return cur;
}

/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	buffersize = size;
	buffer = (char *) calloc(size, sizeof(char));
	bufferpointer = buffer;
	memcpy(buffer, data, size);

	if(!sigsetjmp(postgre_exit, 0)){
		postgre_started = true;
		PostgresSingleUserMain(5, av, "fuzzuser");
	}
	pq_endmsgread();
	postgre_started = false;
	free(buffer);
	return 0;
}
