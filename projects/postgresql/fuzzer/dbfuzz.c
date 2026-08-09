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
///////////////////////////////////////////////////////////////////////////

/*-------------------------------------------------------------------------
 *
 * 
 * This code is released under the terms of the PostgreSQL License.
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *-------------------------------------------------------------------------
 */
#include "postgres_fe.h"

#include <sys/stat.h>
#include <sys/wait.h>

#include "common/logging.h"
#include "common/restricted_token.h"
#include "libpq/pqcomm.h"
#include "pg_config_paths.h"
#include "pg_regress.h"

const char *progname = "progname";
static char *shellprog = SHELLPROG;
char *outputdir = ".";
static char *temp_instance = NULL;
static int port = -1;
static const char *sockdir;
static PID_TYPE postmaster_pid = INVALID_PID;

static void psql_command(const char *database, const char *query, ...) {
  char query_formatted[1024];
  char query_escaped[2048];
  char psql_cmd[MAXPGPATH + 2048];
  va_list args;
  char *s;
  char *d;

  va_start(args, query);
  vsnprintf(query_formatted, sizeof(query_formatted), query, args);
  va_end(args);

  d = query_escaped;
  for (s = query_formatted; *s; s++) {
    if (strchr("\\\"$`", *s))
      *d++ = '\\';
    *d++ = *s;
  }
  *d = '\0';

  snprintf(psql_cmd, sizeof(psql_cmd), "\"%s%spsql\" -X -c \"%s\" \"%s\"",
           "", "", query_escaped, database);

  system(psql_cmd);
}

PID_TYPE
spawn_process(const char *cmdline) {
  pid_t pid;
  pid = fork();
  if (pid == 0) {
    char *cmdline2;
    cmdline2 = psprintf("exec %s", cmdline);
    execl(shellprog, shellprog, "-c", cmdline2, (char *)NULL);
    fprintf(stderr, _("%s: could not exec \"%s\": %s\n"), progname, shellprog,
            strerror(errno));
    _exit(1);
  }

  return pid;
}

int main() {
  int i;
  char buf[MAXPGPATH * 4];
  char buf2[MAXPGPATH * 4];
  char *db_name = "./dbfuzz";
  int wait_seconds = 60;

  pg_logging_init(db_name);
  progname = get_progname(db_name);
  set_pglocale_pgservice(db_name, PG_TEXTDOMAIN("pg_dbfuzz"));
  get_restricted_token();

  temp_instance = make_absolute_path("./temp");
  port = 0xC000 | (PG_VERSION_NUM & 0x3FFF);
  outputdir = make_absolute_path(outputdir);
  sockdir = mkdtemp(psprintf("/tmp/pg_dbfuzz-XXXXXX"));
  putenv(psprintf("PGHOST=%s", sockdir));

  mkdir(temp_instance, S_IRWXU | S_IRWXG | S_IRWXO);

  snprintf(buf, sizeof(buf), "%s/log", outputdir);
  mkdir(buf, S_IRWXU | S_IRWXG | S_IRWXO);

  snprintf(buf, sizeof(buf),
           "\"%s%sinitdb\" -D \"%s/data\" --no-clean --no-sync > "
           "\"%s/log/initdb.log\" 2>&1",
           "", "", temp_instance, outputdir);
  system(buf);

  snprintf(buf, sizeof(buf), "%s/data/postgresql.conf", temp_instance);

  snprintf(buf2, sizeof(buf2), "\"%s%spsql\" -X postgres <%s 2>%s", "", "",
           DEVNULL, DEVNULL);

  snprintf(buf, sizeof(buf),
           "\"%s%spostgres\" -D \"%s/data\" -F%s "
           "-c \"listen_addresses=%s\" -k \"%s\" "
           "> \"%s/log/postmaster.log\" 2>&1",
           "", "", temp_instance, "", "", sockdir, outputdir);

  postmaster_pid = spawn_process(buf);

  for (i = 0; i < wait_seconds; i++) {
    if (system(buf2) == 0)
      break;
    waitpid(postmaster_pid, NULL, WNOHANG);
    pg_usleep(1000000L);
  }

  psql_command("postgres", "CREATE DATABASE \"%s\" TEMPLATE=template0%s",
               "dbfuzz", "");

  snprintf(buf, sizeof(buf), "\"%s%spg_ctl\" stop -D \"%s/data\" -s", "",
           "", temp_instance);
  system(buf);

  rmdir(sockdir);
  return 0;
}
