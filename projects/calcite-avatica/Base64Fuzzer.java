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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.IOException;
import org.apache.calcite.avatica.util.Base64;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// Heuristic name: jvm-autofuzz-heuristics-1
// Target method: [org.apache.calcite.avatica.util.Base64] public static java.lang.String encodeBytes(byte[],int) throws java.io.IOException
public class Base64Fuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      if (data.consumeBoolean()) {
        Base64.encodeBytes(data.consumeRemainingAsBytes());
      } else {
        Base64.decode(data.consumeRemainingAsBytes());
      }
    } catch (IOException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
