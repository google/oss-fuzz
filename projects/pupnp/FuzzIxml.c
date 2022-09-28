/* Copyright 2022 Google LLC
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

#include "ixml.h"
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define kMinInputLength 10
#define kMaxInputLength 5120

int CheckXML(char *filename){

    int rc;
    DOMString s;
    IXML_Document *doc = NULL;

    rc = ixmlLoadDocumentEx(filename, &doc);
    if (rc != IXML_SUCCESS) {
        return rc;
    }

    s = ixmlPrintDocument(doc);
    if (s == NULL || s[0] == '\0') {
        ixmlDocument_free(doc);
        return 1;
    }

    ixmlFreeDOMString(s);
    ixmlDocument_free(doc);

    return 0;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 1;
    }
    
    int ret;
    char filename[256];

    sprintf(filename, "/tmp/libfuzzer.%d", getpid());
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }

    fwrite(Data, Size, 1, fp);
    fclose(fp);

    ret = CheckXML(filename);
    unlink(filename);
    return ret;
}
