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
import org.bytedeco.javacpp.tools.Info;
import org.bytedeco.javacpp.tools.InfoMap;

// jvm-autofuzz-heuristics-2
// Heuristic name: jvm-autofuzz-heuristics-2
// Target method: [org.bytedeco.javacpp.tools.InfoMap] public org.bytedeco.javacpp.tools.Info getFirst(java.lang.String,boolean)
// Target method: [org.bytedeco.javacpp.tools.InfoMap] public org.bytedeco.javacpp.tools.Info get(int,java.lang.String,boolean)
public class JavacppFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    InfoMap obj = new InfoMap();
    Boolean bool = data.consumeBoolean();

    if (data.consumeBoolean()) {
      obj.getFirst(data.consumeRemainingAsString(), bool);
    } else {
      obj.get(data.consumeInt(), data.consumeRemainingAsString(), bool);
    }
  }
}
