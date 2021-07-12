/* Copyright 2021 Google LLC

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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "StdAfx.h"

#include "Common/MyException.h"
#include "Common/StdOutStream.h"
#include "Common/UTFConvert.h"
#include "Common/MyXml.h"

#include "Windows/ErrorMsg.h"
#include "Windows/NtCheck.h"

#include "../../../C/LzmaDec.h"
#include "../../../C/Alloc.h"
#include "Common/MyString.h"


using namespace NWindows;

CStdOutStream *g_StdStream = NULL;
CStdOutStream *g_ErrStream = NULL;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
        if (size < 10 || size > 500) {
            return 0;
        }
        char *new_str = (char *)malloc(size+1);
        if (new_str == NULL){
                return 0;
        }
        memcpy(new_str, data, size);
        new_str[size] = '\0';

        StringsAreEqualNoCase_Ascii(new_str, new_str);

        AString as(new_str);
        int val = as.ReverseFind('M');
        as.RemoveChar('B');


        // UTF8 logic
        CheckUTF8(new_str, true);
        UString dst;
        ConvertUTF8ToUnicode(as, dst);


        // XML
        CXml val_xml;
        val_xml.Parse(new_str);

        free(new_str);
        return 0;
}
