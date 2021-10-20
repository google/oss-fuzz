/*
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// for h3NeighborRotations
#include "algos.h"
#include "h3api.h"
#include "utility.h"

static const Direction DIGITS[7] = {CENTER_DIGIT,  K_AXES_DIGIT, J_AXES_DIGIT,
                                    JK_AXES_DIGIT, I_AXES_DIGIT, IK_AXES_DIGIT,
                                    IJ_AXES_DIGIT};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(H3Index)) {
    return 0;
  }
  H3Index h3;
  memcpy(&h3, data, sizeof(H3Index));

  H3Index input[] = {h3, h3};
  int inputSize = sizeof(input) / sizeof(H3Index);

  // fuzz compactCells
  H3Index *compacted = calloc(inputSize, sizeof(H3Index));
  H3Error errCompact = compactCells(input, compacted, inputSize);

  // fuzz uncompactCells
  int compactedCount = 0;
  for (int i = 0; i < inputSize; i++) {
    if (compacted[i] != 0) {
      compactedCount++;
    }
  }
  if (compactedCount < 2) {
    int uncompactRes = 10;
    int64_t uncompactedSize;
    H3Error err2 =
        uncompactCellsSize(compacted, inputSize, uncompactRes, &uncompactedSize);

    H3Index *uncompacted = calloc(uncompactedSize, sizeof(H3Index));
    H3Error err3 = uncompactCells(compacted, compactedCount, uncompacted,
                                  uncompactedSize, uncompactRes);
    free(uncompacted);
  }

  // fuzz h3NeighborRotations
  int rotations = 0;
  for (int i = 0; i < 7; i++) {
    H3Index neighborRotationsOut;
    h3NeighborRotations(h3, DIGITS[i], &rotations, &neighborRotationsOut);
  }
  free(compacted);
  return 0;
}
