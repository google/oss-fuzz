#include <stdint.h>
#include "lcms2.h"

#define NPOINTS_IT8 10  // (17*17*17*17)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if (size < 8){
        return 0;
    }

    cmsContext context = cmsCreateContext(NULL, (void *)data);

    uint32_t Row = *((uint32_t *)data);
    uint32_t Col = *((uint32_t *)data+1);

    /* Write */
    cmsHANDLE  it8;
    cmsInt32Number i;

    it8 = cmsIT8Alloc(0);
    if (it8 == NULL) return 0;

    cmsIT8SetSheetType(it8, "LCMS/TESTING");
    cmsIT8SetPropertyStr(it8, "ORIGINATOR",   "1 2 3 4");
    cmsIT8SetPropertyUncooked(it8, "DESCRIPTOR",   "1234");
    cmsIT8SetPropertyStr(it8, "MANUFACTURER", "3");
    cmsIT8SetPropertyDbl(it8, "CREATED",     (data[0] % 256) / 255.0);
    cmsIT8SetPropertyDbl(it8, "SERIAL",      (data[1] % 256) / 255.0);
    cmsIT8SetPropertyHex(it8, "MATERIAL",     0x123);

    cmsIT8SetPropertyDbl(it8, "NUMBER_OF_SETS", NPOINTS_IT8); // ?
    cmsIT8SetPropertyDbl(it8, "NUMBER_OF_FIELDS", Row);

    cmsIT8SetDataFormat(it8, 0, "SAMPLE_ID");
    cmsIT8SetDataFormat(it8, 1, "RGB_R");
    cmsIT8SetDataFormat(it8, 2, "RGB_G");
    cmsIT8SetDataFormat(it8, 3, "RGB_B");

    for (i=0; i < NPOINTS_IT8; i++) {

          char Patch[20];

          sprintf(Patch, "P%d", i);

          cmsIT8SetDataRowCol(it8, i, 0, Patch);
          cmsIT8SetDataRowColDbl(it8, i, 1, i);
          cmsIT8SetDataRowColDbl(it8, i, 2, i);
          cmsIT8SetDataRowColDbl(it8, i, 3, i);
    }

    cmsIT8SaveToFile(it8, "TEST.IT8");
    cmsIT8Free(it8);

    it8 = cmsIT8LoadFromFile(0, "TEST.IT8");
    if (it8 == NULL) return 0;

    /* Read */
    cmsIT8GetDataRowColDbl(it8,Row,Col);
    cmsIT8GetPropertyDbl(it8, "DESCRIPTOR");
    cmsIT8GetDataDbl(it8, "P3", "RGB_G");

    cmsIT8Free(it8);
    return 1;
}
