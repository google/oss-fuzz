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
    
    if (size < sizeof(cmsViewingConditions)) {
        return 0;
    }

    // Define and initialize the viewing conditions structure
    cmsViewingConditions viewingConditions;
    viewingConditions.whitePoint.X = data[0]/ 255.0;
    viewingConditions.whitePoint.Y = data[1]/ 255.0;
    viewingConditions.whitePoint.Z = data[2]/ 255.0;
    viewingConditions.Yb = data[3] / 255.0;
    viewingConditions.La = data[4]/ 255.0;
    viewingConditions.surround = data[5] % 4 + 1; //from 1 to 4
    viewingConditions.D_value = data[6] / 255.0;

    cmsContext context = cmsCreateContext(NULL, NULL);

    cmsHANDLE hModel = cmsCIECAM02Init(context, &viewingConditions);

    if (hModel) {
        // Perform forward and reverse CAM02 transformations with appropriate input data
        cmsCIEXYZ inputXYZ;
        inputXYZ.X = data[0]/ 255.0;  // Random value between 0 and 1
        inputXYZ.Y = data[1] / 255.0;
        inputXYZ.Z = data[2] / 255.0;
        cmsJCh outputJCh;
        cmsCIEXYZ outputXYZ;
        cmsCIECAM02Forward(hModel, &inputXYZ, &outputJCh);
        cmsCIECAM02Reverse(hModel, &outputJCh, &outputXYZ);
        cmsCIECAM02Done(hModel);
    }
    cmsDeleteContext(context);

    return 0;
}
