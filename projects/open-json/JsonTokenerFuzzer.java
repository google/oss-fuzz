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
import org.json.JSONException;
import org.json.JSONTokener;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-1
// Heuristic name: jvm-autofuzz-heuristics-1
// Target method: [org.json.JSONTokener] public static int dehexchar(char)
// jvm-autofuzz-heuristics-2
// Heuristic name: jvm-autofuzz-heuristics-2
// Target method: [org.json.JSONTokener] public java.lang.String nextTo(java.lang.String)
// Target method: [org.json.JSONTokener] public java.lang.String nextString(char) throws org.json.JSONException
// Target method: [org.json.JSONTokener] public char next(char) throws org.json.JSONException
// Target method: [org.json.JSONTokener] public java.lang.String next(int) throws org.json.JSONException
// Target method: [org.json.JSONTokener] public java.lang.String nextTo(char)
// Target method: [org.json.JSONTokener] public void skipPast(java.lang.String)
public class JsonTokenerFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    JSONTokener obj = new JSONTokener(data.consumeString(data.remainingBytes() / 2));

    try {
      switch(data.consumeInt(1, 7)) {
        case 1:
          obj.nextTo(data.consumeRemainingAsString());
          break;
        case 2:
          JSONTokener.dehexchar(data.consumeChar());
          break;
        case 3:
          obj.nextString(data.consumeChar());
          break;
        case 4:
          obj.nextString(data.consumeChar());
          break;
        case 5:
          obj.next(data.consumeInt());
          break;
        case 6:
          obj.nextTo(data.consumeChar());
          break;
        case 7:
          obj.skipPast(data.consumeString(100));
          break;
      }
    } catch(JSONException | StringIndexOutOfBoundsException e1) {
      // Known exception
    }
  }
}
