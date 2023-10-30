#include <stdint.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    
    if (size < sizeof(cmsViewingConditions)) {
        return 0;
    }

    // Define and initialize the viewing conditions structure
    cmsViewingConditions viewingConditions;
    viewingConditions.whitePoint.X = (data[0] % 256) / 255.0;
    viewingConditions.whitePoint.Y = (data[1] % 256) / 255.0;
    viewingConditions.whitePoint.Z = (data[2] % 256) / 255.0;
    viewingConditions.Yb = (data[3] % 256) / 255.0;
    viewingConditions.La = (data[4] % 256) / 255.0;
    viewingConditions.surround = data[5] % 4 + 1; //from 1 to 4
    viewingConditions.D_value = (data[6] % 256) / 255.0;

    cmsContext context = cmsCreateContext(NULL, NULL);

    cmsHANDLE hModel = cmsCIECAM02Init(context, &viewingConditions);

    if (hModel) {
        // Perform forward and reverse CAM02 transformations with appropriate input data
        cmsCIEXYZ inputXYZ;
        inputXYZ.X = (data[0] % 256) / 255.0;  // Random value between 0 and 1
        inputXYZ.Y = (data[1] % 256) / 255.0;
        inputXYZ.Z = (data[2] % 256) / 255.0;
        cmsJCh outputJCh;
        cmsCIEXYZ outputXYZ;
        cmsCIECAM02Forward(hModel, &inputXYZ, &outputJCh);
        cmsCIECAM02Reverse(hModel, &outputJCh, &outputXYZ);
        cmsCIECAM02Done(hModel);
    }
    cmsDeleteContext(context);

    return 0;
}
