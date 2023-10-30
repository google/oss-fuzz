#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

wchar_t* generateWideString(){
    char* characters = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    char stringToWide[10];
    for (int i=0; i < 9; i++){
        stringToWide[i] = characters[rand() % 96];
    }
    stringToWide[9] = '\0';
    int requiredSize = mbstowcs(NULL, &stringToWide, 0);
    wchar_t* wideString = (wchar_t *)malloc( (requiredSize + 1) * sizeof( wchar_t ));
    mbstowcs(wideString, &stringToWide, requiredSize+1);
    return wideString;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12){
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
    srand(*data);
    wchar_t* wideString = generateWideString();
    cmsMLUsetWide(mlu, "en", "US", wideString);
    free(wideString);
    
    
    char ObtainedLanguage[3], ObtainedCountry[3];
    ObtainedLanguage[0] = characters[*data % 96];
    ObtainedLanguage[1] = characters[*(data+1) % 96];
    ObtainedLanguage[2] = characters[*(data+2) % 96];

    ObtainedCountry[0] = characters[*(data+2) % 96];
    ObtainedCountry[1] = characters[*data % 96];
    ObtainedCountry[2] = characters[*(data+1) % 96];
    cmsMLUgetTranslation(mlu, "en", "US",ObtainedLanguage,ObtainedCountry);
    cmsMLUtranslationsCount(mlu);
    cmsMLUtranslationsCodes(mlu, *((uint32_t *)data), ObtainedLanguage, ObtainedCountry);

    cmsMLU* displayName = mlu;
    cmsMLU* displayValue = mlu;

    //cmsDictAddEntry
    wchar_t* name = generateWideString();
    wchar_t* value = generateWideString();
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
