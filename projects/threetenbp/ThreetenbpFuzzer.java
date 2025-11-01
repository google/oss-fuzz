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
import java.util.EnumSet;
import java.util.Locale;
import org.threeten.bp.format.DateTimeFormatter;
import org.threeten.bp.format.DateTimeParseException;
import org.threeten.bp.format.FormatStyle;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-1
// Heuristic name: jvm-autofuzz-heuristics-1
// Target method: [org.threeten.bp.format.DateTimeFormatter] public static
// org.threeten.bp.format.DateTimeFormatter ofPattern(java.lang.String)
public class ThreetenbpFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      DateTimeFormatter formatter = null;
      switch (data.consumeInt(1, 6)) {
        case 1:
          formatter = DateTimeFormatter.ofPattern(data.consumeString(data.remainingBytes() / 2));
          break;
        case 2:
          formatter = DateTimeFormatter.ofPattern(
              data.consumeString(data.remainingBytes() / 2), Locale.ROOT);
          break;
        case 3:
          formatter =
              DateTimeFormatter.ofLocalizedDate(data.pickValue(EnumSet.allOf(FormatStyle.class)));
          break;
        case 4:
          formatter =
              DateTimeFormatter.ofLocalizedTime(data.pickValue(EnumSet.allOf(FormatStyle.class)));
          break;
        case 5:
          formatter = DateTimeFormatter.ofLocalizedDateTime(
              data.pickValue(EnumSet.allOf(FormatStyle.class)));
          break;
        case 6:
          formatter = DateTimeFormatter.ofLocalizedDateTime(
              data.pickValue(EnumSet.allOf(FormatStyle.class)),
              data.pickValue(EnumSet.allOf(FormatStyle.class)));
          break;
      }
      if (formatter != null) {
        formatter.parse(data.consumeRemainingAsString());
      }
    } catch (DateTimeParseException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
