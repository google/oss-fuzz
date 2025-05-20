#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// 被测试的函数声明
extern int check(const char *s);

// C 链接符号：LLVMFuzzerTestOneInput
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *s = (char *)malloc(size + 1);
    memcpy(s, data, size);
    s[size] = '\0';
    check(s);
    free(s);
    return 0;
}

