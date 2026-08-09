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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.ObjectReader;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.datatype.joda.JodaModule;
import org.joda.time.*;

import java.io.IOException;
import java.util.*;

public class JodaMapperFuzzer {
    public static DateTimeFeature[] dateTimeFeatures = new DateTimeFeature[]{
            DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS,
            DateTimeFeature.WRITE_DURATIONS_AS_TIMESTAMPS,
            DateTimeFeature.WRITE_DATES_WITH_ZONE_ID,
    };

    public static Class[] classes = { DummyClass.class, DateTimeZone.class, Date.class, DateTime.class, org.joda.time.Duration.class,
            org.joda.time.Instant.class, org.joda.time.LocalDateTime.class, org.joda.time.LocalDate.class, org.joda.time.LocalTime.class, org.joda.time.Period.class, ReadablePeriod.class,
            ReadableDateTime.class, ReadableInstant.class, Interval.class, MonthDay.class, YearMonth.class };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        JsonMapper.Builder builder = JsonMapper.builder()
                .addModule(new JodaModule());
        
        boolean writeDatesAsTimestamps = data.consumeBoolean();
        builder.configure(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS, writeDatesAsTimestamps);

        List<DateTimeFeature> pickedValues = data.pickValues(dateTimeFeatures,
                data.consumeInt(0, dateTimeFeatures.length));
        for (DateTimeFeature feature : pickedValues) {
            builder.enable(feature);
        }
        
        JsonMapper jodaMapper = builder.build();
        ObjectReader reader = jodaMapper.readerFor(data.pickValue(classes));

        try {
            reader.readValue(data.consumeRemainingAsString());
        } catch (IllegalArgumentException | ArithmeticException | MismatchedInputException e) {}
    }

    public static class DummyClass {
        public Date date;
        public TimeZone timeZone;
        public Calendar calendar;
        public Locale locale;
        public org.joda.time.Duration duration;
        public org.joda.time.LocalDateTime localDateTime;
        public org.joda.time.LocalDate localDate;
        public org.joda.time.LocalTime localTime;
        public org.joda.time.Period period;
        public ReadablePeriod readablePeriod;
        public ReadableDateTime readableDateTime;
        public ReadableInstant readableInstant;
        public Interval instant;
        public MonthDay monthDay;
        public YearMonth yearMonth;
        public DateTimeZone dateTimeZone;
    }
}
