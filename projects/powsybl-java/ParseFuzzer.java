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
import java.time.format.DateTimeParseException;

public class ParseFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      byte[] bytes = data.consumeRemainingAsBytes();
      JsonParser parser;
      String str;
      ByteArrayInputStream bais;
      InputStreamReader reader;
      switch (data.consumeInt(1, 16)) {
        case 1:
          bais = new ByteArrayInputStream(bytes);
          reader = new InputStreamReader(bais);
      	  FullModel.parse(reader);
          break;
        case 2:
          str = new String(bytes, StandardCharsets.UTF_8);
          Partition.parse(str);
          break;
        case 3:
          bais = new ByteArrayInputStream(bytes);
          new BoundaryPointXlsParser().parse(bais);
          break;
        case 4:
          str = new String(bytes, StandardCharsets.UTF_8);
          EntsoeFileName.parse(str);
          break;
        case 5:
          parser = new JsonFactory().createParser(bytes);
          SensitivityFactor.parseJson(parser);
          break;
        case 6:
          parser = new JsonFactory().createParser(bytes);
          SensitivityValue.parseJson(parser);
          break;
        case 7:
          parser = new JsonFactory().createParser(bytes);
          SensitivityVariableSet.parseJson(parser);
          break;
        case 8:
          parser = new JsonFactory().createParser(bytes);
          WeightedSensitivityVariable.parseJson(parser);
          break;
        case 9:
          parser = new JsonFactory().createParser(bytes);
          SensitivityContingencyStatus.parseJson(parser);
          break;
        case 10:
          parser = new JsonFactory().createParser(bytes);
          InfiniteTimeSeriesIndex.parseJson(parser);
          break;
        case 11:
          parser = new JsonFactory().createParser(bytes);
          IrregularTimeSeriesIndex.parseJson(parser);
          break;
        case 12:
          parser = new JsonFactory().createParser(bytes);
          RegularTimeSeriesIndex.parseJson(parser);
          break;
        case 13:
          bais = new ByteArrayInputStream(bytes);
          reader = new InputStreamReader(bais);
          Project.parseJson(reader);
          break;
        case 14:
          bais = new ByteArrayInputStream(bytes);
          reader = new InputStreamReader(bais);
          StudyCase.parseJson(reader);
          break;
        case 15:
          parser = new JsonFactory().createParser(bytes);
          NodeCalc.parseJson(parser);
          break;
        case 16:
          str = new String(bytes, StandardCharsets.UTF_8);
          TimeSeries.parseCsv(str);
          break;
      }

      // Fuzz parse methods

      // Fuzz other parse methods
    } catch (PowsyblException
        | IOException
        | UncheckedIOException
        | UncheckedXmlStreamException
        | IllegalArgumentException
        | DateTimeParseException e) {
      // Fuzzer: silently ignore
    }
  }
}
