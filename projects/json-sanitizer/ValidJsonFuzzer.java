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

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.json.JsonSanitizer;

public class ValidJsonFuzzer {
  private static Gson gson = new Gson();

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String input = data.consumeRemainingAsString();
    String output;
    try {
      output = JsonSanitizer.sanitize(input, 10);
    } catch (ArrayIndexOutOfBoundsException e) {
      // ArrayIndexOutOfBoundsException is expected if nesting depth is
      // exceeded.
      return;
    }
    try {
      gson.fromJson(output, JsonElement.class);
    } catch (Exception e) {
      System.err.println("input  : " + input);
      System.err.println("output : " + output);
      throw e;
    }
  }
}
