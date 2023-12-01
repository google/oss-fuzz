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
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.fasterxml.jackson.datatype.joda.deser.DateTimeDeserializer;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Duration;
import org.joda.time.Instant;
import org.joda.time.Interval;
import org.joda.time.LocalDate;
import org.joda.time.LocalDateTime;
import org.joda.time.LocalTime;
import org.joda.time.MonthDay;
import org.joda.time.Period;
import org.joda.time.ReadableDateTime;
import org.joda.time.ReadableInstant;
import org.joda.time.ReadablePeriod;
import org.joda.time.YearMonth;

/** This fuzzer targets the deserialization methods of joda objects */
public class JodaDeserializerFuzzer {
  private static ObjectMapper mapper;
  private static ObjectMapper plainMapper;
  private static List<Class> choice;
  private static List<TypeReference> typeChoice;

  public static void fuzzerInitialize() {
    // Register the JodaModule for the deserialization
    mapper = new ObjectMapper().registerModule(new JodaModule());
    plainMapper = new ObjectMapper();
    initializeClassChoice();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the deserialize methods for different joda objects
      Class classReference = data.pickValue(choice);
      TypeReference typeReference = data.pickValue(typeChoice);
      String value = data.consumeRemainingAsString();
      mapper.readValue(value, classReference);
      mapper.readValue(value, typeReference);
      plainMapper.readValue(value, AnnotationClass.class);
    } catch (IOException | IllegalArgumentException | ArithmeticException | UnsupportedOperationException e) {
      // Known exception
    }
  }

  private static void initializeClassChoice() {
    choice = new ArrayList<Class>();
    typeChoice = new ArrayList<TypeReference>();

    choice.add(DateTime.class);
    choice.add(DateTimeContainer.class);
    choice.add(DateTimeZone.class);
    choice.add(DateTimeZoneContainer.class);
    choice.add(Duration.class);
    choice.add(Instant.class);
    choice.add(Interval.class);
    choice.add(LocalDate.class);
    choice.add(LocalDateTime.class);
    choice.add(LocalTime.class);
    choice.add(MonthDay.class);
    choice.add(Period.class);
    choice.add(ReadableDateTime.class);
    choice.add(ReadableDateTimeContainer.class);
    choice.add(ReadableInstant.class);
    choice.add(ReadablePeriod.class);
    choice.add(YearMonth.class);

    typeChoice.add(new TypeReference<Map<DateTime, String>>() {});
    typeChoice.add(new TypeReference<Map<LocalDate, String>>() {});
    typeChoice.add(new TypeReference<Map<LocalTime, String>>() {});
    typeChoice.add(new TypeReference<Map<LocalDateTime, String>>() {});
  }

  private static class ReadableDateTimeContainer {
    @JsonFormat(without = JsonFormat.Feature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE)
    public ReadableDateTime readableDateTime;
  }

  private static class DateTimeContainer {
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    public DateTime dateTime;

    public DateTime getDateTime() {
      return dateTime;
    }
  }

  private static class DateTimeZoneContainer {
    @JsonTypeInfo(
        use = JsonTypeInfo.Id.CLASS,
        include = JsonTypeInfo.As.WRAPPER_ARRAY,
        property = "@class")
    public DateTimeZone dateTimeZone;

    public DateTimeZoneContainer(DateTimeZone dateTimeZone) {
      this.dateTimeZone = dateTimeZone;
    }
  }

  private static class AnnotationClass {
    @JsonDeserialize(using = DateTimeDeserializer.class)
    private DateTime dateTime;

    public void setDateTime(DateTime dateTime) {
      this.dateTime = dateTime;
    }
  }
}
