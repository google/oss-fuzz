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
import org.apache.ibatis.io.ResolverUtil;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-10
// Heuristic name: jvm-autofuzz-heuristics-10
// Target method: [org.apache.ibatis.io.ResolverUtil] public org.apache.ibatis.io.ResolverUtil findAnnotated(java.lang.Class,java.lang.String[])
// Target method: [org.apache.ibatis.io.ResolverUtil] public org.apache.ibatis.io.ResolverUtil findImplementations(java.lang.Class,java.lang.String[])
public class ResolverUtilFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    ResolverUtil obj = new ResolverUtil();

    if (data.consumeBoolean()) {
      obj.findAnnotated(
          ResolverUtilFuzzer.class, new java.lang.String[] {data.consumeRemainingAsString()});
    } else {
      obj.findImplementations(
          ResolverUtilFuzzer.class, new java.lang.String[] {data.consumeRemainingAsString()});
    }
  }
}
