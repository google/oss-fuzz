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


import org.jfree.chart.JFreeChart;
import org.jfree.chart.ChartFactory;
import org.jfree.data.time.*;
import ossfuzz.TestUtils;

public class TimeSeriesChartFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        RegularTimePeriod t = new Day();
        TimeSeries<String> series = new TimeSeries<>(data.consumeString(100));
        Integer numItems = data.consumeInt(0, 1000);
        for (int i = 0; i < numItems; i++) {
            series.add(t, data.consumeInt());
            if (i != numItems - 1) {
                t = t.next();
            }
        }
        TimeSeriesCollection<String> dataset = new TimeSeriesCollection<>();
        dataset.addSeries(series);

        JFreeChart c1 = ChartFactory.createTimeSeriesChart(
                data.consumeString(100),
                data.consumeString(100),
                data.consumeString(100),
                dataset);
        JFreeChart c2 = TestUtils.serialised(c1);
        if (!c1.equals(c2)) {
            throw new Exception("Charts with Time Series should be equal");
        }
    }
}
