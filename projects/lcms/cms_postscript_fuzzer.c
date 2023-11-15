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

#include <stdint.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if (size < 16) {
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, (void *)data);
    if (!context){
        return 0;
    }

    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (!hProfile){
        return 0;
    }

    uint32_t flags         = *((const uint32_t *)data+2);
    uint32_t intent        = *((const uint32_t *)data+3) % 16;
    
    /* cmsGetPostScriptCSA */
    cmsUInt32Number result1 = cmsGetPostScriptCSA(context, hProfile, intent, flags, NULL, size);
    /* cmsGetPostScriptCRD */
    cmsUInt32Number result2 = cmsGetPostScriptCRD(context, hProfile, intent, flags,  NULL, size);

    cmsCloseProfile(hProfile);
    cmsDeleteContext(context);

    return 0;
}
