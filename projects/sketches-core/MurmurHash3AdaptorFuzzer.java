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
import org.apache.datasketches.hash.MurmurHash3Adaptor;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-1
// Heuristic name: jvm-autofuzz-heuristics-1
// Target method: [org.apache.datasketches.hash.MurmurHash3Adaptor] public static byte[] hashToBytes(java.lang.String,long)
// Target method: [org.apache.datasketches.hash.MurmurHash3Adaptor] public static long[] hashToLongs(int[],long)
public class MurmurHash3AdaptorFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Long longValue = data.consumeLong();

    if (data.consumeBoolean()) {
      MurmurHash3Adaptor.hashToBytes(data.consumeRemainingAsString(), longValue);
    } else {
      MurmurHash3Adaptor.hashToLongs(data.consumeInts(data.remainingBytes() / 4), longValue);
    }
  }
}
