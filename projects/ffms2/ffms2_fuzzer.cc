/* Copyright 2023 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <ffms.h>
#include <string>

#include <sys/types.h>
#include <unistd.h>


/* Overwrite atexit to make linker happy */
int atexit(void (*function)(void)) {
  return 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FFMS_Init(0, 0);

  char errmsg[1024];
  FFMS_ErrorInfo errinfo;
  errinfo.Buffer = errmsg;
  errinfo.BufferSize = sizeof(errmsg);
  errinfo.ErrorType = FFMS_ERROR_SUCCESS;
  errinfo.SubType = FFMS_ERROR_SUCCESS;

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  FFMS_Indexer *indexer = FFMS_CreateIndexer(filename, &errinfo);
  if (indexer != NULL) {
    FFMS_Index *index = FFMS_DoIndexing2(indexer, FFMS_IEH_ABORT, &errinfo);
    if (index != NULL) {
      int trackno = FFMS_GetFirstTrackOfType(index, FFMS_TYPE_VIDEO, &errinfo);
    }
    FFMS_DestroyIndex(index);
  }

  unlink(filename);

  return 0;
}
