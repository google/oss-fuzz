#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int load_env_from_file(char* filename);

int g_log_level = 0;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/tmp/hami_env_file_%d", getpid());
    FILE* f = fopen(path, "wb");
    if (f == NULL)
        return 0;
    fwrite(data, 1, size, f);
    fclose(f);
    load_env_from_file(path);
    unlink(path);
    return 0;
}
