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


import java.io.InputStream;
import java.io.ByteArrayInputStream;
import org.HdrHistogram.Histogram;
import org.HdrHistogram.EncodableHistogram;
import org.HdrHistogram.HistogramLogReader;

public class LogReaderWriterFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int numberOfSignificantValueDigits = data.consumeInt(0, 5);
        byte [] input = data.consumeRemainingAsBytes();
        if (input.length == 0) {
            return;
        }
        EncodableHistogram encodeableHistogram = null;
        Histogram accumulatedHistogram = new Histogram(numberOfSignificantValueDigits);
        InputStream readerStream = new ByteArrayInputStream(input);
        HistogramLogReader reader = new HistogramLogReader(readerStream);
        while ((encodeableHistogram = reader.nextIntervalHistogram()) != null) {
            Histogram histogram = (Histogram) encodeableHistogram;
            histogram.getTotalCount();
            accumulatedHistogram.add(histogram);
        }
    }
}
