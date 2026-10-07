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
import org.atteo.evo.inflector.English;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-1
// Heuristic name: jvm-autofuzz-heuristics-1
// Target method: [org.atteo.evo.inflector.English] public static java.lang.String
// plural(java.lang.String)
public class EnglishFuzzer {
  private static English.MODE[] mode = {
      English.MODE.ENGLISH_ANGLICIZED, English.MODE.ENGLISH_CLASSICAL};

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    English.setMode(data.pickValue(mode));
    Boolean choice = data.consumeBoolean();
    if (choice) {
      English.plural(data.consumeRemainingAsString());
    } else {
      Integer int1 = data.consumeInt();
      English.plural(data.consumeRemainingAsString(), int1);
    }
  }
}
