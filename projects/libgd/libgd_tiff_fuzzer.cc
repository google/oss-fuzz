#include "gd.h"
#include<stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
      gdImagePtr im;    
      im = gdImageCreateFromTiffPtr(Size, (void *) Data);
      free(im);
}
