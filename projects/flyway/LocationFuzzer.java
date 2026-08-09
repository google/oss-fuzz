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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import java.util.regex.PatternSyntaxException;
import org.flywaydb.core.api.FlywayException;
import org.flywaydb.core.api.Location;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-11
// Heuristic name: jvm-autofuzz-heuristics-11
// Target method: [org.flywaydb.core.api.Location] public  <init>(java.lang.String)
public class LocationFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      new Location(data.consumeRemainingAsString());
    } catch (FlywayException e) {
      // Known exception
    }
  }
}
