#include <stdint.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (!hProfile){
        return 0;
    }
    //cmsMD5computeID
    cmsMD5computeID(hProfile);
    cmsCloseProfile(hProfile);
    return 0;
}
