#include <stdint.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if (size < 16) {
        return 0;
    }
    //cmsGBDAlloc
    cmsHANDLE hGDB = cmsGBDAlloc(NULL);
    if (!hGDB){
        return 0;
    }
    //cmsGDBAddPoint
    cmsCIELab Lab;
    Lab.L = *((const uint32_t *)data);
    Lab.a = *((const uint32_t *)data+1);
    Lab.b = *((const uint32_t *)data+2);
    cmsGDBAddPoint(hGDB, &Lab);
    
    //cmsGDBCheckPoint
    cmsGDBCheckPoint(hGDB, &Lab);

    //cmsGDBCompute
    cmsGDBCompute(hGDB, *((const uint32_t *)data+3));

    //cmsGBDFree
    cmsGBDFree(hGDB);

    return 0;
}
