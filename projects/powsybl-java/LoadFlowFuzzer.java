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
import com.powsybl.cgmes.conversion.*;
import com.powsybl.commons.*;
import com.powsybl.commons.datasource.*;
import com.powsybl.commons.report.*;
import com.powsybl.computation.local.*;
import com.powsybl.contingency.*;
import com.powsybl.ieeecdf.converter.*;
import com.powsybl.iidm.network.*;
import com.powsybl.loadflow.*;
import com.powsybl.loadflow.LoadFlowParameters.*;
import com.powsybl.matpower.converter.*;
import com.powsybl.nad.*;
import com.powsybl.openloadflow.*;
import com.powsybl.powerfactory.converter.*;
import com.powsybl.powerfactory.model.*;
import com.powsybl.psse.converter.*;
import com.powsybl.security.*;
import com.powsybl.sensitivity.*;
import com.powsybl.shortcircuit.*;
import com.powsybl.sld.*;
import com.powsybl.ucte.converter.*;
import com.univocity.parsers.common.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class LoadFlowFuzzer {
  private static Path tempFile;

  public static void fuzzerInitialize() {
    try {
      tempFile = Files.createTempFile("fuzz-", "-fuzz");
      tempFile.toFile().deleteOnExit();
    } catch (Throwable ignored) {
      tempFile = null;
    }
  }

  private static Contingency getContingency(FuzzedDataProvider data) {
    List<ContingencyElement> allElements = new ArrayList<>();
    allElements.add(new BatteryContingency("fuzz"));
    allElements.add(new BranchContingency("fuzz"));
    allElements.add(new BusbarSectionContingency("fuzz"));
    allElements.add(new BusContingency("fuzz"));
    allElements.add(new DanglingLineContingency("fuzz"));
    allElements.add(new GeneratorContingency("fuzz"));
    allElements.add(new HvdcLineContingency("fuzz"));
    allElements.add(new LineContingency("fuzz"));
    allElements.add(new LoadContingency("fuzz"));
    allElements.add(new ShuntCompensatorContingency("fuzz"));
    allElements.add(new StaticVarCompensatorContingency("fuzz"));
    allElements.add(new SwitchContingency("fuzz"));
    allElements.add(new ThreeWindingsTransformerContingency("fuzz"));
    allElements.add(new TieLineContingency("fuzz"));
    allElements.add(new TwoWindingsTransformerContingency("fuzz"));

    // Build random contingency with repetition
    Contingency contingency = new Contingency("Fuzz");
    for (Integer i = 0; i < 10; i++) {
      ContingencyElement elem = allElements.get(data.consumeInt(0, allElements.size() - 1));
      contingency.addElement(elem);
    }
    return contingency;
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // 14 Doubles + 11 Integers + 15 Booleans + 7 pick values + bytes for network
    Integer requiredBytes = (14 * 8) + (11 * 4) + (15 * 1) + (7 * 4) + 1;
    if ((data.remainingBytes() < requiredBytes) || (tempFile == null)) {
      return;
    }

    // Make the fuzzer consume this first. Do not call
    // any data.consume*() methods before this
    byte[] loadBytes = data.consumeBytes(10000);

    try {
      Importer importer = null;
      int choice = data.consumeInt(1, 6);
      double[] randomDouble = new double[12];
      for (int i = 0; i < randomDouble.length; i++) {
        randomDouble[i] = data.consumeDouble();
      }

      Contingency contingency = getContingency(data);

      LoadFlowParameters loadFlowParameters = new LoadFlowParameters();
      loadFlowParameters.setBalanceType(data.pickValue(EnumSet.allOf(BalanceType.class)));
      loadFlowParameters.setVoltageInitMode(data.pickValue(EnumSet.allOf(VoltageInitMode.class)));
      loadFlowParameters.setConnectedComponentMode(
          data.pickValue(EnumSet.allOf(ConnectedComponentMode.class)));
      loadFlowParameters.setDc(data.consumeBoolean());
      loadFlowParameters.setDcPowerFactor(data.consumeProbabilityDouble());
      loadFlowParameters.setDcUseTransformerRatio(data.consumeBoolean());
      loadFlowParameters.setDistributedSlack(data.consumeBoolean());
      loadFlowParameters.setHvdcAcEmulation(data.consumeBoolean());
      loadFlowParameters.setNoGeneratorReactiveLimits(data.consumeBoolean());
      loadFlowParameters.setPhaseShifterRegulationOn(data.consumeBoolean());
      loadFlowParameters.setReadSlackBus(data.consumeBoolean());
      loadFlowParameters.setShuntCompensatorVoltageControlOn(data.consumeBoolean());
      loadFlowParameters.setSimulShunt(data.consumeBoolean());
      loadFlowParameters.setTransformerVoltageControlOn(data.consumeBoolean());
      loadFlowParameters.setTwtSplitShuntAdmittance(data.consumeBoolean());
      loadFlowParameters.setUseReactiveLimits(data.consumeBoolean());

      ContingencyContext context =
          new ContingencyContext("ID", data.pickValue(EnumSet.allOf(ContingencyContextType.class)));
      SensitivityFactor factor =
          new SensitivityFactor(
              data.pickValue(EnumSet.allOf(SensitivityFunctionType.class)),
              "ID",
              data.pickValue(EnumSet.allOf(SensitivityVariableType.class)),
              "ID",
              data.consumeBoolean(),
              context);

      Properties properties = new Properties();
      properties.setProperty("solver", data.pickValue(new String[] {"DEFAULT", "NEWTON", "GAUSS"}));
      properties.setProperty("convergence", String.valueOf(data.consumeDouble()));

      ReadOnlyMemDataSource ds = new ReadOnlyMemDataSource();
      switch (choice) {
        case 1:
          ds.putData("fuzz", loadBytes);
          importer = new CgmesImport();
          break;
        case 2:
          ds.putData(".txt", loadBytes);
          importer = new IeeeCdfImporter();
          break;
        case 3:
          ds.putData(".mat", loadBytes);
          importer = new MatpowerImporter();
          break;
        case 4:
          ds.putData(".dgs", loadBytes);
          byte[] loadBytes2 = data.consumeBytes(10000);
          ds.putData(".json", loadBytes2);
          importer = new PowerFactoryImporter();
          break;
        case 5:
          ds.putData(".raw", loadBytes);
          importer = new PsseImporter();
          break;
        case 6:
          ds.putData(".uct", loadBytes);
          importer = new UcteImporter();
          break;
        default:
          return;
      }

      if (importer != null) {
        Network network = null;
        try {
          network = importer.importData(ds, NetworkFactory.findDefault(), properties);
        } catch (NullPointerException e) {
          if (importer instanceof PowerFactoryImporter) {
            // Wrong format handling
            return;
          } else {
            throw e;
          }
        }
        if (network.getBusView().getBuses().spliterator().getExactSizeIfKnown() > 0
            && network.getGeneratorCount() > 0) {

          for (Bus bus : network.getBusView().getBuses()) {
            bus.setV(Math.abs(randomDouble[0]));
            bus.setAngle(randomDouble[1]);
          }
          for (Generator generator : network.getGenerators()) {
            generator.setMaxP(Math.abs(randomDouble[2]));
            generator.setMinP(Math.max(0, randomDouble[3]));
            generator.setTargetV(randomDouble[4]);
            generator.setTargetP(randomDouble[5]);
            generator.setTargetQ(randomDouble[6]);
            generator.setRatedS(Math.max(1.0, randomDouble[7]));
          }
          for (Load load : network.getLoads()) {
            load.setP0(randomDouble[8]);
            load.setQ0(randomDouble[9]);
          }
          for (Line line : network.getLines()) {
            line.setR(randomDouble[10]);
            line.setX(randomDouble[11]);
          }

          LoadFlow.run(network, loadFlowParameters);
          new OpenLoadFlowProvider()
              .run(
                  network,
                  LocalComputationManager.getDefault(),
                  "Fuzz",
                  loadFlowParameters,
                  ReportNode.NO_OP);

          List<Fault> faults = new ArrayList<>();
          faults.add(new BranchFault("id", "elemId", randomDouble[12]));
          faults.add(new BusFault("id", "elemId"));
          ShortCircuitAnalysis.run(network, faults);

          List<Contingency> contingencies = new ArrayList<>();
          contingencies.add(contingency);
          SecurityAnalysis.run(network, contingencies);

          List<SensitivityFactor> factors = new ArrayList<>();
          factors.add(factor);
          SensitivityAnalysis.run(network, factors);

          if (tempFile != null) {
            NetworkAreaDiagram.draw(network, tempFile);
            SingleLineDiagram.draw(network, "fuzz", tempFile);
          }
        }
      }
    } catch (PowsyblException
        | UncheckedIOException
        | PowerFactoryException
        | IllegalArgumentException
        | TextParsingException e) {
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
