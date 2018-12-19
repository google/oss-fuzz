#include "sass.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char* sass_data = (char*) malloc(sizeof(char) * size + 1);
  if (sass_data == NULL) return 0;

  memcpy(sass_data, data, size);
  sass_data[size] = '\0';

  struct Sass_Data_Context* ctx = sass_make_data_context(sass_data);
  if (ctx == NULL) {
    free(sass_data);
    return 0;
  }

  struct Sass_Options* options = sass_make_options();
  if (options == NULL) {
    sass_delete_data_context(ctx);
    return 0;
  }

  sass_option_set_output_style(options, SASS_STYLE_NESTED);
  sass_option_set_precision(options, 5);

  sass_data_context_set_options(ctx, options);
  sass_compile_data_context(ctx);

  sass_delete_data_context(ctx);
  sass_delete_options(options);

  return 0;
}
