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
import org.apache.commons.lang3.CharSequenceUtils;
import org.apache.commons.lang3.CharSetUtils;
import org.apache.commons.lang3.CharUtils;

/** This fuzzer targets the methods of the Char related utils classes. */
public class CharUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 10);

      switch (choice) {
        case 1:
          CharSequenceUtils.subSequence(data.consumeRemainingAsString(), 0);
          break;
        case 2:
          CharSequenceUtils.toCharArray(data.consumeRemainingAsString());
          break;
        case 3:
          CharSetUtils.containsAny(
              data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          break;
        case 4:
          CharSetUtils.count(
              data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          break;
        case 5:
          CharSetUtils.delete(
              data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          break;
        case 6:
          CharSetUtils.keep(
              data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          break;
        case 7:
          CharSetUtils.squeeze(
              data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          break;
        case 8:
          CharUtils.isAsciiAlphanumeric(data.consumeChar());
          break;
        case 9:
          CharUtils.toCharacterObject(data.consumeRemainingAsString());
          break;
        case 10:
          CharUtils.unicodeEscaped(data.consumeChar());
          break;
      }
    } catch (IllegalArgumentException e) {
      // Known exception
    }
  }
}
