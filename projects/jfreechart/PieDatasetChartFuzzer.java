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
import org.jfree.data.general.DefaultPieDataset;
import ossfuzz.TestUtils;


public class PieDatasetChartFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) throws Exception {
        DefaultPieDataset<String> dataSet = new DefaultPieDataset<>();
        Integer numValues = data.consumeInt(0, 1000);
        for (int i = 0 ; i < numValues; i++) {
            dataSet.setValue(data.consumeString(100), data.consumeDouble());
        }

        JFreeChart c1 = ChartFactory.createPieChart(data.consumeString(100), dataSet);
        JFreeChart c2 = TestUtils.serialised(c1);
        if (!c1.equals(c2)) {
            throw new Exception("Charts with Pie Datasets should be equal");
        }
    }
}
