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
