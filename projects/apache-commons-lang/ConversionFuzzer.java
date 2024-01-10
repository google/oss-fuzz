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
import org.apache.commons.lang3.Conversion;

/** This fuzzer targets the methods of the Conversion class */
public class ConversionFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 15);
      Integer size = data.consumeInt(1, 5);
      Integer remaining = data.remainingBytes();

      switch (choice) {
        case 1:
          Conversion.binaryBeMsb0ToHexDigit(data.consumeBooleans(data.consumeInt(1, 5)));
          break;
        case 2:
          Conversion.binaryToByte(data.consumeBooleans(size), 0, (byte) 0, 0, size);
          break;
        case 3:
          Conversion.binaryToHexDigit(data.consumeBooleans(data.consumeInt(1, 5)));
          break;
        case 4:
          Conversion.binaryToHexDigitMsb0_4bits(data.consumeBooleans(data.consumeInt(1, 5)));
          break;
        case 5:
          Conversion.binaryToInt(data.consumeBooleans(data.consumeInt(1, 5)), 0, 0, 0, size);
          break;
        case 6:
          Conversion.binaryToLong(data.consumeBooleans(data.consumeInt(1, 5)), 0, 0l, 0, size);
          break;
        case 7:
          Conversion.binaryToShort(
              data.consumeBooleans(data.consumeInt(1, 5)), 0, (short) 0, 0, size);
          break;
        case 8:
          Conversion.byteArrayToInt(data.consumeRemainingAsBytes(), 0, 0, 0, remaining);
          break;
        case 9:
          Conversion.byteArrayToLong(data.consumeRemainingAsBytes(), 0, 0l, 0, remaining);
          break;
        case 10:
          Conversion.byteArrayToShort(data.consumeRemainingAsBytes(), 0, (short) 0, 0, remaining);
          break;
        case 11:
          Conversion.byteArrayToUuid(data.consumeRemainingAsBytes(), 0);
          break;
        case 12:
          Conversion.hexToByte(data.consumeRemainingAsString(), 0, (byte) 0, 0, remaining);
          break;
        case 13:
          Conversion.hexToInt(data.consumeRemainingAsString(), 0, 0, 0, remaining);
          break;
        case 14:
          Conversion.hexToLong(data.consumeRemainingAsString(), 0, 0l, 0, remaining);
          break;
        case 15:
          Conversion.hexToShort(data.consumeRemainingAsString(), 0, (short) 0, 0, remaining);
          break;
      }
    } catch (IllegalArgumentException | NullPointerException | IndexOutOfBoundsException e) {
      // Known exception
    }
  }
}
