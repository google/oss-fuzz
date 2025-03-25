// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
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
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.powsybl.cgmes.model.FullModel;
import com.powsybl.commons.PowsyblException;
import com.powsybl.commons.exceptions.UncheckedXmlStreamException;
import com.powsybl.computation.Partition;
import com.powsybl.entsoe.util.BoundaryPointXlsParser;
import com.powsybl.entsoe.util.EntsoeFileName;
import com.powsybl.powerfactory.model.Project;
import com.powsybl.powerfactory.model.StudyCase;
import com.powsybl.sensitivity.SensitivityAnalysisResult.SensitivityContingencyStatus;
import com.powsybl.sensitivity.SensitivityFactor;
import com.powsybl.sensitivity.SensitivityValue;
import com.powsybl.sensitivity.SensitivityVariableSet;
import com.powsybl.sensitivity.WeightedSensitivityVariable;
import com.powsybl.timeseries.InfiniteTimeSeriesIndex;
import com.powsybl.timeseries.IrregularTimeSeriesIndex;
import com.powsybl.timeseries.RegularTimeSeriesIndex;
import com.powsybl.timeseries.TimeSeries;
import com.powsybl.timeseries.ast.NodeCalc;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

public class ParseFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      byte[] bytes = data.consumeRemainingAsBytes();
      String str = new String(bytes, StandardCharsets.UTF_8);
      ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
      InputStreamReader reader = new InputStreamReader(bais);
      JsonParser parser = new JsonFactory().createParser(bytes);

      // Fuzz parse methods
      FullModel.parse(reader);
      Partition.parse(str);
      new BoundaryPointXlsParser().parse(bais);
      EntsoeFileName.parse(str);

      // Fuzz other parse methods
      SensitivityFactor.parseJson(parser);
      SensitivityValue.parseJson(parser);
      SensitivityVariableSet.parseJson(parser);
      WeightedSensitivityVariable.parseJson(parser);
      SensitivityContingencyStatus.parseJson(parser);
      InfiniteTimeSeriesIndex.parseJson(parser);
      IrregularTimeSeriesIndex.parseJson(parser);
      RegularTimeSeriesIndex.parseJson(parser);
      Project.parseJson(reader);
      StudyCase.parseJson(reader);
      NodeCalc.parseJson(parser);
      TimeSeries.parseCsv(str);
    } catch (PowsyblException
        | IOException
        | UncheckedIOException
        | UncheckedXmlStreamException
        | IllegalArgumentException e) {
      // Fuzzer: silently ignore
    }
  }
}
