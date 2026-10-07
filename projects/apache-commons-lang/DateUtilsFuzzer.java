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
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;

/** This fuzzer targets the methods of the classes in the time package. */
public class DateUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Calendar calendar = Calendar.getInstance();
      Date date = new Date();
      Integer choice = data.consumeInt(1, 13);

      switch (choice) {
        case 1:
          DateFormatUtils.format(calendar, data.consumeRemainingAsString());
          break;
        case 2:
          DateFormatUtils.formatUTC(date, data.consumeRemainingAsString());
          break;
        case 3:
          DateUtils.parseDate(
              data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          break;
        case 4:
          DateUtils.parseDate(
              data.consumeString(data.remainingBytes()),
              Locale.getDefault(),
              data.consumeRemainingAsString());
          break;
        case 5:
          DateUtils.parseDateStrictly(
              data.consumeString(data.remainingBytes()), data.consumeRemainingAsString());
          break;
        case 6:
          DateUtils.parseDateStrictly(
              data.consumeString(data.remainingBytes()),
              Locale.getDefault(),
              data.consumeRemainingAsString());
          break;
        case 7:
          DateUtils.round(date, data.consumeInt());
          break;
        case 8:
          DateUtils.round(calendar, data.consumeInt());
          break;
        case 9:
          DateUtils.truncatedEquals(
              calendar, DateUtils.truncate(calendar, data.consumeInt()), data.consumeInt());
          break;
        case 10:
          DateUtils.truncatedEquals(
              date, DateUtils.truncate(date, data.consumeInt()), data.consumeInt());
          break;
        case 11:
          DurationFormatUtils.formatDuration(data.consumeLong(), data.consumeRemainingAsString());
          break;
        case 12:
          DurationFormatUtils.formatDurationWords(
              data.consumeLong(), data.consumeBoolean(), data.consumeBoolean());
          break;
        case 13:
          DurationFormatUtils.formatPeriod(
              data.consumeLong(), data.consumeLong(), data.consumeRemainingAsString());
          break;
      }
    } catch (ParseException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
