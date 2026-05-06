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
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.datatype.joda.JodaModule;
import tools.jackson.datatype.joda.ser.DateTimeSerializer;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.exc.MismatchedInputException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.joda.time.Interval;
import org.joda.time.Period;

/** This fuzzer targets the serialization methods of joda objects */
public class JodaSerializerFuzzer {
  private static ObjectMapper mapper;
  private static ObjectMapper plainMapper;

  public static void fuzzerInitialize() {
    // Register the JodaModule for the serialization
    plainMapper = new ObjectMapper();
    mapper = tools.jackson.databind.json.JsonMapper.builder()
            .addModule(new JodaModule())
            .enable(tools.jackson.databind.cfg.DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(tools.jackson.databind.cfg.DateTimeFeature.WRITE_DURATIONS_AS_TIMESTAMPS)
            .build();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Fuzz the serialize methods for different joda objects
      mapper = tools.jackson.databind.json.JsonMapper.builder()
              .addModule(new JodaModule())
              .configure(tools.jackson.databind.cfg.DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS, data.consumeBoolean())
              .build();
      DateTime dateTime = new DateTime(data.consumeLong());
      switch (data.consumeInt(1, 11)) {
        case 1:
          plainMapper.writeValueAsString(new AnnotationClass(dateTime));
          break;
        case 2:
          mapper.writeValueAsString(dateTime);
          break;
        case 3:
          mapper
              .writer()
              .without(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
              .writeValueAsString(dateTime);
          break;
        case 4:
          Map<String, Object> map = new HashMap<String, Object>();
          map.put(data.consumeRemainingAsString(), dateTime);
          mapper.writeValueAsString(map);
          break;
        case 5:
          mapper.writeValueAsString(dateTime.toInstant());
          break;
        case 6:
          mapper.writeValueAsString(new Interval(dateTime.toInstant(), dateTime.toInstant()));
          break;
        case 7:
          mapper.writeValueAsString(dateTime.toLocalDate());
          break;
        case 8:
          mapper.writeValueAsString(dateTime.toLocalTime());
          break;
        case 9:
          mapper.writeValueAsString(dateTime.toLocalDateTime());
          break;
        case 10:
          mapper.writeValueAsString(new Duration(dateTime.toInstant(), dateTime.toInstant()));
          break;
        case 11:
          mapper.writeValueAsString(new Period(dateTime.getMillis()));
          break;
      }
    } catch (IllegalArgumentException | ArithmeticException | MismatchedInputException e) {
      // Known exception
    }
  }

  private static class AnnotationClass {
    @JsonSerialize(using = DateTimeSerializer.class)
    private DateTime dateTime;

    public AnnotationClass(DateTime dateTime) {
      this.dateTime = dateTime;
    }

    public DateTime getDateTime() {
      return this.dateTime;
    }
  }
}
