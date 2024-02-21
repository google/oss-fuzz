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
#include <stdlib.h>
#include "lcms2.h"

wchar_t* generateWideString(const char* characters, const uint8_t *data){
    if (!characters){
        return NULL;
    }
    
    char stringToWide[10];
    for (int i = 0; i < 9; i++){
        stringToWide[i] = characters[data[i] % 95];
    }
    stringToWide[9] = '\0';
    
    int requiredSize = mbstowcs(NULL, stringToWide, 0);
    wchar_t* wideString = (wchar_t *)malloc((requiredSize + 1) * sizeof(wchar_t));
    mbstowcs(wideString, stringToWide, requiredSize + 1);
    return wideString;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 27){
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, (void *)data);
    if (!context) {
        return 0;
    }

    // Create a Dictionary handle
    cmsHANDLE hDict = cmsDictAlloc(context);
    if (!hDict) {
        return 0;
    }
    

    cmsMLU *mlu = cmsMLUalloc(hDict, 0);
    if (!mlu) {
        return 0;
    }
    
    char* characters = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    wchar_t* wideString = generateWideString(characters, data);
    cmsMLUsetWide(mlu, "en", "US", wideString);
    free(wideString);
    
    
    char ObtainedLanguage[3], ObtainedCountry[3];
    ObtainedLanguage[0] = characters[*(data+1) % 95];
    ObtainedLanguage[1] = characters[*(data+2) % 95];
    ObtainedLanguage[2] = characters[*(data) % 95];

    ObtainedCountry[0] = characters[*(data+2) % 95];
    ObtainedCountry[1] = characters[*data % 95];
    ObtainedCountry[2] = characters[*(data+1) % 95];
    cmsMLUgetTranslation(mlu, "en", "US",ObtainedLanguage,ObtainedCountry);
    cmsMLUtranslationsCount(mlu);
    cmsMLUtranslationsCodes(mlu, *((uint32_t *)data), ObtainedLanguage, ObtainedCountry);

    cmsMLU* displayName = mlu;
    cmsMLU* displayValue = mlu;

    //cmsDictAddEntry
    wchar_t* name = generateWideString(characters, data + 9);
    wchar_t* value = generateWideString(characters, data + 18);
    cmsDictAddEntry(hDict, name, value, displayName, displayValue);
    free(name);
    free(value);

    //cmsDictDup
    cmsHANDLE ResultDictDup = cmsDictDup(hDict);
    if (ResultDictDup) {
        cmsDictFree(ResultDictDup);
    }
    // Iterate over the Dictionary entries
    const cmsDICTentry* entry = cmsDictGetEntryList(hDict);
    cmsDictNextEntry(entry);
    cmsMLUfree(mlu);
    cmsDictFree(hDict);
    return 0;
}
