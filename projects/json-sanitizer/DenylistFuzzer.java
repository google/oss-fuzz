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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import com.google.json.JsonSanitizer;

public class DenylistFuzzer {
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

    // Check for forbidden substrings. As these would enable Cross-Site
    // Scripting, treat every finding as a high severity vulnerability.
    assert !output.contains("</script")
        : new FuzzerSecurityIssueHigh("Output contains </script");
    assert !output.contains("]]>")
        : new FuzzerSecurityIssueHigh("Output contains ]]>");

    // Check for more forbidden substrings. As these would not directly enable
    // Cross-Site Scripting in general, but may impact script execution on the
    // embedding page, treat each finding as a medium severity vulnerability.
    assert !output.contains("<script")
        : new FuzzerSecurityIssueMedium("Output contains <script");
    assert !output.contains("<!--")
        : new FuzzerSecurityIssueMedium("Output contains <!--");
  }
}
