#include "linenoise.c"

void linenoiseWrapper(char* buf, size_t buflen) {
  linenoiseEdit(STDIN_FILENO, STDOUT_FILENO, buf, buflen, "");
}
