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
import kong.unirest.core.json.JsonEngine;
import kong.unirest.core.json.JSONException;
import kong.unirest.jackson.JacksonEngine;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-2
// Heuristic name: jvm-autofuzz-heuristics-2
// Target method: [kong.unirest.jackson.JacksonEngine] public kong.unirest.core.json.JsonEngine$Object newEngineObject(java.lang.String) throws kong.unirest.core.json.JSONExce>
public class JacksonEngineFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      JacksonEngine obj = new JacksonEngine();
      obj.newEngineObject(data.consumeRemainingAsString());
    } catch (JSONException e1) {
      // Known exception
    }
  }
}
