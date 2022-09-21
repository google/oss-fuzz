#include "builtin.h"

int cmd_version(int argc, const char **argv, const char *prefix);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size <= 10) {
      return 0;
   }

   int path = (*((int *)data))%2;
   data += 4;
   size -= 4;

   int argc;
   char *argv[2];

   switch(path) {
      // Without option
      default:
         case 0:
            argv[0] = (char *) data;
            argc = 1;
            break;

         // With option
         case 1:
            argv[0] = (char *) data;
            argv[1] = "--build-options";
            argc = 2;
            break;
   }

   cmd_version(argc, (const char **)argv, (const char *)"");

   return 0;
}
