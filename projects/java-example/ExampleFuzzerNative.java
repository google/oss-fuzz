// Copyright 2021 Google LLC
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

public class ExampleFuzzerNative {
  static {
    System.loadLibrary("native");
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    int val = data.consumeInt();
    String stringData = data.consumeRemainingAsString();
    if (val == 17759716 && stringData.length() > 10 && stringData.contains("jazzer")) {
      // call native function which contains a crash
      parse(stringData);
    }
  }

  private static native boolean parse(String bytes);
}
