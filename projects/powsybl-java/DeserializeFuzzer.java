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
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.DefaultDeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.powsybl.action.json.ActionListDeserializer;
import com.powsybl.action.json.DanglingLineActionBuilderBuilderDeserializer;
import com.powsybl.action.json.GeneratorActionBuilderDeserializer;
import com.powsybl.action.json.HvdcActionBuilderDeserializer;
import com.powsybl.action.json.LoadActionBuilderBuilderDeserializer;
import com.powsybl.action.json.MultipleActionsActionBuilderDeserializer;
import com.powsybl.action.json.PercentChangeLoadActionBuilderDeserializer;
import com.powsybl.action.json.PhaseTapChangerRegulationActionBuilderBuilderDeserializer;
import com.powsybl.action.json.PhaseTapChangerTapPositionActionBuilderDeserializer;
import com.powsybl.action.json.RatioTapChangerRegulationActionBuilderBuilderDeserializer;
import com.powsybl.action.json.RatioTapChangerTapPositionActionBuilderDeserializer;
import com.powsybl.action.json.ShuntCompensatorPositionActionBuilderDeserializer;
import com.powsybl.action.json.StaticVarCompensatorActionBuilderDeserializer;
import com.powsybl.action.json.SwitchActionBuilderDeserializer;
import com.powsybl.action.json.TerminalsConnectionActionBuilderDeserializer;
import com.powsybl.commons.PowsyblException;
import com.powsybl.contingency.contingency.list.IdentifierContingencyListDeserializer;
import com.powsybl.contingency.json.ContingencyDeserializer;
import com.powsybl.contingency.json.ContingencyElementDeserializer;
import com.powsybl.contingency.json.ContingencyListDeserializer;
import com.powsybl.contingency.json.DefaultContingencyListDeserializer;
import com.powsybl.contingency.json.HvdcLineCriterionContingencyListDeserializer;
import com.powsybl.contingency.json.InjectionCriterionContingencyListDeserializer;
import com.powsybl.contingency.json.LineCriterionContingencyListDeserializer;
import com.powsybl.contingency.json.ListOfContingencyListsDeserializer;
import com.powsybl.contingency.json.ThreeWindingsTransformerCriterionContingencyListDeserializer;
import com.powsybl.contingency.json.TieLineCriterionContingencyListDeserializer;
import com.powsybl.contingency.json.TwoWindingsTransformerCriterionContingencyListDeserializer;
import com.powsybl.iidm.criteria.json.CriterionDeserializer;
import com.powsybl.iidm.criteria.json.DanglingLineCriterionDeserializer;
import com.powsybl.iidm.criteria.json.IdentifiableCriterionDeserializer;
import com.powsybl.iidm.criteria.json.LineCriterionDeserializer;
import com.powsybl.iidm.criteria.json.NetworkElementIdListCriterionDeserializer;
import com.powsybl.iidm.criteria.json.ThreeWindingsTransformerCriterionDeserializer;
import com.powsybl.iidm.criteria.json.TieLineCriterionDeserializer;
import com.powsybl.iidm.criteria.json.TwoWindingsTransformerCriterionDeserializer;
import com.powsybl.iidm.criteria.json.VoltageIntervalDeserializer;
import com.powsybl.iidm.criteria.json.duration.AllTemporaryDurationCriterionDeserializer;
import com.powsybl.iidm.criteria.json.duration.EqualityTemporaryDurationCriterionDeserializer;
import com.powsybl.iidm.criteria.json.duration.IntervalTemporaryDurationCriterionDeserializer;
import com.powsybl.iidm.criteria.json.duration.PermanentDurationCriterionDeserializer;
import com.powsybl.iidm.geodata.utils.GeoShapeDeserializer;
import com.powsybl.iidm.network.identifiers.json.IdentifierDeserializer;
import com.powsybl.sensitivity.json.SensitivityContingencyStatusJsonDeserializer;
import com.powsybl.sensitivity.json.SensitivityFactorJsonDeserializer;
import com.powsybl.sensitivity.json.SensitivityValueJsonDeserializer;
import com.powsybl.sensitivity.json.SensitivityVariableSetJsonDeserializer;
import com.powsybl.shortcircuit.json.ShortCircuitParametersDeserializer;
import com.powsybl.shortcircuit.json.VoltageRangeDeserializer;
import com.powsybl.timeseries.json.DataChunkJsonDeserializer;
import com.powsybl.timeseries.json.DoubleDataChunkJsonDeserializer;
import com.powsybl.timeseries.json.DoubleTimeSeriesJsonDeserializer;
import com.powsybl.timeseries.json.NodeCalcJsonDeserializer;
import com.powsybl.timeseries.json.StringDataChunkJsonDeserializer;
import com.powsybl.timeseries.json.StringTimeSeriesJsonDeserializer;
import com.powsybl.timeseries.json.TimeSeriesJsonDeserializer;
import com.powsybl.timeseries.json.TimeSeriesMetadataJsonDeserializer;
import java.io.IOException;
import java.io.UncheckedIOException;

public class DeserializeFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      StdDeserializer<? extends Object> deserializer = null;

      byte[] bytes = data.consumeBytes(50000);
      Integer choice = data.consumeInt(1, 56);

      switch (choice) {
        case 1:
          deserializer = new ActionListDeserializer();
          break;
        case 2:
          deserializer = new DanglingLineActionBuilderBuilderDeserializer();
          break;
        case 3:
          deserializer = new GeneratorActionBuilderDeserializer();
          break;
        case 4:
          deserializer = new HvdcActionBuilderDeserializer();
          break;
        case 5:
          deserializer = new LoadActionBuilderBuilderDeserializer();
          break;
        case 6:
          deserializer = new MultipleActionsActionBuilderDeserializer();
          break;
        case 7:
          deserializer = new PercentChangeLoadActionBuilderDeserializer();
          break;
        case 8:
          deserializer = new PhaseTapChangerRegulationActionBuilderBuilderDeserializer();
          break;
        case 9:
          deserializer = new PhaseTapChangerTapPositionActionBuilderDeserializer();
          break;
        case 10:
          deserializer = new RatioTapChangerRegulationActionBuilderBuilderDeserializer();
          break;
        case 11:
          deserializer = new RatioTapChangerTapPositionActionBuilderDeserializer();
          break;
        case 12:
          deserializer = new ShuntCompensatorPositionActionBuilderDeserializer();
          break;
        case 13:
          deserializer = new StaticVarCompensatorActionBuilderDeserializer();
          break;
        case 14:
          deserializer = new SwitchActionBuilderDeserializer();
          break;
        case 15:
          deserializer = new TerminalsConnectionActionBuilderDeserializer();
          break;
        case 16:
          deserializer = new DanglingLineCriterionDeserializer();
          break;
        case 17:
          deserializer = new IdentifiableCriterionDeserializer();
          break;
        case 18:
          deserializer = new CriterionDeserializer();
          break;
        case 19:
          deserializer = new TieLineCriterionDeserializer();
          break;
        case 20:
          deserializer = new LineCriterionDeserializer();
          break;
        case 21:
          deserializer = new ThreeWindingsTransformerCriterionDeserializer();
          break;
        case 22:
          deserializer = new NetworkElementIdListCriterionDeserializer();
          break;
        case 23:
          deserializer = new VoltageIntervalDeserializer();
          break;
        case 24:
          deserializer = new PermanentDurationCriterionDeserializer();
          break;
        case 25:
          deserializer = new IntervalTemporaryDurationCriterionDeserializer();
          break;
        case 26:
          deserializer = new EqualityTemporaryDurationCriterionDeserializer();
          break;
        case 27:
          deserializer = new AllTemporaryDurationCriterionDeserializer();
          break;
        case 28:
          deserializer = new TwoWindingsTransformerCriterionDeserializer();
          break;
        case 29:
          deserializer = new IdentifierDeserializer();
          break;
        case 30:
          deserializer = new GeoShapeDeserializer();
          break;
        case 31:
          deserializer = new SensitivityContingencyStatusJsonDeserializer();
          break;
        case 32:
          deserializer = new SensitivityFactorJsonDeserializer();
          break;
        case 33:
          deserializer = new SensitivityValueJsonDeserializer();
          break;
        case 34:
          deserializer = new SensitivityVariableSetJsonDeserializer();
          break;
        case 35:
          deserializer = new ShortCircuitParametersDeserializer();
          break;
        case 36:
          deserializer = new VoltageRangeDeserializer();
          break;
        case 37:
          deserializer = new DataChunkJsonDeserializer();
          break;
        case 38:
          deserializer = new DoubleDataChunkJsonDeserializer();
          break;
        case 39:
          deserializer = new DoubleTimeSeriesJsonDeserializer();
          break;
        case 40:
          deserializer = new NodeCalcJsonDeserializer();
          break;
        case 41:
          deserializer = new StringDataChunkJsonDeserializer();
          break;
        case 42:
          deserializer = new StringTimeSeriesJsonDeserializer();
          break;
        case 43:
          deserializer = new TimeSeriesJsonDeserializer();
          break;
        case 44:
          deserializer = new TimeSeriesMetadataJsonDeserializer();
          break;
        case 45:
          deserializer = new IdentifierContingencyListDeserializer();
          break;
        case 46:
          deserializer = new ContingencyDeserializer();
          break;
        case 47:
          deserializer = new ContingencyListDeserializer();
          break;
        case 48:
          deserializer = new ContingencyElementDeserializer();
          break;
        case 49:
          deserializer = new DefaultContingencyListDeserializer();
          break;
        case 50:
          deserializer = new HvdcLineCriterionContingencyListDeserializer();
          break;
        case 51:
          deserializer = new InjectionCriterionContingencyListDeserializer();
          break;
        case 52:
          deserializer = new LineCriterionContingencyListDeserializer();
          break;
        case 53:
          deserializer = new ListOfContingencyListsDeserializer();
          break;
        case 54:
          deserializer = new ThreeWindingsTransformerCriterionContingencyListDeserializer();
          break;
        case 55:
          deserializer = new TieLineCriterionContingencyListDeserializer();
          break;
        case 56:
          deserializer = new TwoWindingsTransformerCriterionContingencyListDeserializer();
          break;
      }

      if (deserializer != null) {
        ObjectMapper mapper = new ObjectMapper();
        JsonFactory factory = mapper.getFactory();
        JsonParser parser = factory.createParser(bytes);

        DeserializationConfig config = mapper.getDeserializationConfig();
        DefaultDeserializationContext defaultContext =
            (DefaultDeserializationContext) mapper.getDeserializationContext();
        DeserializationContext context =
            defaultContext.createInstance(config, parser, mapper.getInjectableValues());

        deserializer.deserialize(parser, context);
      }
    } catch (PowsyblException
        | IOException
        | IllegalArgumentException
        | IllegalStateException
        | UncheckedIOException e) {
      // Fuzzer: silently ignore
    } catch (NullPointerException e) {
      // Capture known NPE from malformed JSON
      if (!isExpected(e)) {
        throw e;
      }
    }
  }

  private static boolean isExpected(Throwable e) {
    String[] expectedString = {
      "java.util.Objects.requireNonNull",
      "Cannot invoke \"String.hashCode()\"",
      "Name is null",
      "Cannot invoke \"com.fasterxml.jackson.databind.JsonNode.get(String)\""
    };

    for (String expected : expectedString) {
      if (e.toString().contains(expected)) {
        return true;
      }
      for (StackTraceElement ste : e.getStackTrace()) {
        if (ste.toString().contains(expected)) {
          return true;
        }
      }
    }

    return false;
  }
}
