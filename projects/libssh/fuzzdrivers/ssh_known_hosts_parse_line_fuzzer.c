#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "libssh/ssh2.h"
#include "libssh/libssh.h"
#include "libssh/server.h"
#include "libssh/sftp.h"
#include "libssh/callbacks.h"
#include "libssh/libssh.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *data = (char *)malloc(Size + 1);
    if (!data)
        return 0;
    memcpy(data, Data, Size);
    data[Size] = '\0';
    struct ssh_knownhosts_entry *entry;
    ssh_known_hosts_parse_line("localhost", data, &entry);
    free(data);
    return 0;
}
