// Copyright 2022 Google LLC
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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;

import org.springframework.classify.PatternMatcher;

import java.util.*;
import java.lang.*;

public class PatternMatcher_match_Fuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    if (data.remainingBytes() < 2)
      return;

    String pattern = data.consumeString(data.consumeInt(0, 1000));
    String str     = data.consumeString(data.consumeInt(0, 1000));

    // Fill the hash map with things
    Map<String, Integer> map = new HashMap<String, Integer>();
    while (data.remainingBytes() > 0) {
        String key = data.consumeString(data.consumeInt(0, 1000));
        Integer val = data.consumeInt(0, 255);
        map.putIfAbsent(key, val);
    }

    PatternMatcher pm = new PatternMatcher(map);
    pm.match(pattern, str);
  }
}
