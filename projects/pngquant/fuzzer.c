// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "rwpng.h"
#include "libimagequant.h"
#include "pngquant_opts.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return 0;

  char img[256];
  sprintf(img, "/tmp/libfuzzer.png");

  FILE *fp = fopen(img, "wb");
  if (!fp)
    return 0;
  fwrite(data, size, 1, fp);
  fclose(fp);

  liq_attr *attr = liq_attr_create();
  png24_image tmp = {.width=0};
  liq_image *input_image = NULL;
  read_image(attr, img, false, &tmp, &input_image, true, true, false);
  
  liq_attr_destroy(attr);
  if(input_image!=NULL){
    liq_image_destroy(input_image);
  }
  rwpng_free_image24(&tmp);
  unlink(img);
  return 0; 
}
