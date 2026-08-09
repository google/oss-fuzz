// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.commons.lang3.math.IEEE754rUtils;
import org.apache.commons.lang3.math.NumberUtils;

/** This fuzzer targets the methods of the classes in the math package. */
public class MathUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 5);

      switch (choice) {
        case 1:
          float[] floats = new float[data.consumeInt(1, 5)];
          for (Integer i = 0; i < floats.length; i++) {
            floats[i] = data.consumeFloat();
          }
          IEEE754rUtils.max(floats);
          IEEE754rUtils.min(floats);
          break;
        case 2:
          double[] doubles = new double[data.consumeInt(1, 5)];
          for (Integer i = 0; i < doubles.length; i++) {
            doubles[i] = data.consumeDouble();
          }
          IEEE754rUtils.max(doubles);
          IEEE754rUtils.min(doubles);
          break;
        case 3:
          NumberUtils.createNumber(data.consumeRemainingAsString());
          break;
        case 4:
          NumberUtils.isCreatable(data.consumeRemainingAsString());
          break;
        case 5:
          NumberUtils.isParsable(data.consumeRemainingAsString());
          break;
      }
    } catch (NumberFormatException e) {
      // Known exception
    }
  }
}
