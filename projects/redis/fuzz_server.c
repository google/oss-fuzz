/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Fuzzes Redis command dispatch: RESP / inline parsing via processInputBuffer().
 */
#include "server.h"

extern void initServerConfig(void);
extern void initServer(void);
extern void InitServerLast(void);
extern int connTypeInitialize(void);

#define kMaxInput (1 << 20)

static int fuzz_deny_dangerous_commands(void) {
  const char *ops[] = {
      "-shutdown",
      "-save",
      "-bgsave",
      "-replicaof",
      "-slaveof",
  };
  size_t i;

  for (i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
    if (ACLSetUser(DefaultUser, ops[i], -1) != C_OK) {
      return 1;
    }
  }
  ACLRecomputeCommandBitsFromCommandRulesAllUsers();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  if (Size == 0 || Size > kMaxInput) {
    return 0;
  }

  server.watchdog_period = 0;
  applyWatchdogPeriod();

  client *c = createClient(NULL);
  if (!c) {
    return 0;
  }
  /* Fuzz input must not leave the client in replica mode across commands (see processCommand). */
  c->flags &= ~CLIENT_SLAVE;

  c->querybuf = sdsnewlen((const char *)Data, Size);
  c->qb_pos = 0;

  (void)processInputBuffer(c);
  freeClient(c);
  return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  initServerConfig();
  resetServerSaveParams();

  ACLInit();
  moduleInitModulesSystem();
  if (connTypeInitialize() != C_OK) {
    return 1;
  }
  server.port = 0;
  server.tls_port = 0;
  server.cluster_enabled = 0;
  initServer();
  InitServerLast();

  if (server.aof_state != AOF_OFF) {
    stopAppendOnly();
  }
  replicationUnsetMaster();

  if (fuzz_deny_dangerous_commands() != 0) {
    return 1;
  }

  return 0;
}
