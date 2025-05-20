#include <stdlib.h>
#include <string.h>
int check(const char *s) {
    // 故意的越界读取漏洞：当 s 长度为 5 时，访问 s[5]
    if (strlen(s) == 5 && s[5] == 'A') return 1;
    return 0;
}
int main(int argc, char **argv) {
    if (argc > 1) check(argv[1]);
    return 0;
}
