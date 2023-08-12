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
import org.joni.Matcher;
import org.joni.Regex;
import org.joni.Syntax;
import org.joni.exception.InternalException;
import org.joni.exception.SyntaxException;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-2
// Heuristic name: jvm-autofuzz-heuristics-2
// Target method: [org.joni.Regex] public org.joni.Matcher matcher(byte[],int,int)
public class RegexMatcherFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer int1 = data.consumeInt();
      Integer int2 = data.consumeInt();
      Regex obj = new Regex(data.consumeString(data.remainingBytes() / 2));
      obj.matcher(data.consumeRemainingAsBytes(), int1, int2);
    } catch (SyntaxException | InternalException | IllegalArgumentException e) {
    }
  }
}
