#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size) {
  if (size < 4) {
    return 0;
  }

  int index = 0;
  if (data[index++] != 'H')
    return 0;

  if (data[index++] != 'e')
    return 0;

  if (data[index++] != 'l')
    return 0;

  if (size < 11) {
    return 0;
  }
  if (data[index++] != 'l')
    return 0;
  if (data[index++] != 'o')
    return 0;
  if (data[index++] != ',')
    return 0;
  if (data[index++] != ' ')
    return 0;
  if (data[index++] != 'W')
    return 0;
  if (data[index++] != 'o')
    return 0;
  if (data[index++] != 'r')
    return 0;
  if (data[index++] != 'l')
    return 0;
  if (data[index++] != 'd')
    return 0;
  if (data[index] != '!')
    return 0;

  uint8_t* x = (uint8_t *) malloc(10);
  free(x);

  return x[8];
}
