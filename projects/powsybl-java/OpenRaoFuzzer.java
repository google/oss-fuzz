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
import com.powsybl.commons.PowsyblException;
import com.powsybl.contingency.ContingencyElementType;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.TwoSides;
import com.powsybl.loadflow.LoadFlowParameters;
import com.powsybl.openrao.commons.Unit;
import com.powsybl.openrao.data.crac.api.Crac;
import com.powsybl.openrao.data.crac.api.CracFactory;
import com.powsybl.openrao.data.crac.api.InstantKind;
import com.powsybl.openrao.data.crac.api.networkaction.ActionType;
import com.powsybl.openrao.data.crac.api.range.RangeType;
import com.powsybl.openrao.data.crac.api.usagerule.UsageMethod;
import com.powsybl.openrao.data.crac.io.commons.iidm.IidmPstHelper;
import com.powsybl.openrao.raoapi.Rao;
import com.powsybl.openrao.raoapi.RaoInput;
import com.powsybl.openrao.raoapi.parameters.RaoParameters;
import com.powsybl.sensitivity.SensitivityAnalysisParameters;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.EnumSet;

public class OpenRaoFuzzer {
  private static Path networkFilePath;

  public static void fuzzerInitialize() {
    try {
      networkFilePath = Files.createTempFile("fuzz-", "-fuzz");
      networkFilePath.toFile().deleteOnExit();
    } catch (Throwable ignored) {
      networkFilePath = null;
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomise variables
      String newString = data.consumeString(1024);
      ContingencyElementType newType = data.pickValue(EnumSet.allOf(ContingencyElementType.class));
      InstantKind newInstant = data.pickValue(EnumSet.allOf(InstantKind.class));
      Unit newUnit = data.pickValue(EnumSet.allOf(Unit.class));
      RangeType newRange = data.pickValue(EnumSet.allOf(RangeType.class));
      UsageMethod newUsage = data.pickValue(EnumSet.allOf(UsageMethod.class));
      ActionType newAction = data.pickValue(EnumSet.allOf(ActionType.class));
      TwoSides newSide = data.pickValue(EnumSet.allOf(TwoSides.class));
      double newMin = data.consumeDouble();
      double newMax = data.consumeDouble();
      int minTap = data.consumeInt();
      int maxTap = data.consumeInt();
      boolean isDc = data.consumeBoolean();

      // Randomise file content
      FileWriter fw = new FileWriter(networkFilePath.toFile());
      fw.write(data.consumeRemainingAsString());
      fw.close();

      // Initialise objects
      Network network = Network.read(networkFilePath);
      Crac crac = CracFactory.findDefault().create("Fuz-Crac");
      IidmPstHelper iidmPstHelper = new IidmPstHelper(newString, network);

      // Randomise Crac object
      crac.newContingency().withId("contingency").withContingencyElement(newString, newType).add();
      crac.newInstant("fuzz-instance", newInstant);

      crac.newFlowCnec()
          .withId("fuzz-flow")
          .withInstant("fuzz-instant")
          .withOptimized()
          .withNetworkElement(newString)
          .newThreshold()
          .withMin(newMin)
          .withMax(newMax)
          .withUnit(newUnit)
          .withSide(newSide)
          .add()
          .add();

      crac.newPstRangeAction()
          .withId("fuzz-action")
          .withNetworkElement(newString)
          .withInitialTap(iidmPstHelper.getInitialTap())
          .withTapToAngleConversionMap(iidmPstHelper.getTapToAngleConversionMap())
          .newTapRange()
          .withMinTap(minTap)
          .withMaxTap(maxTap)
          .withRangeType(newRange)
          .add()
          .newOnInstantUsageRule()
          .withInstant("fuzz-instant")
          .withUsageMethod(newUsage)
          .add()
          .add();

      crac.newNetworkAction()
          .withId("fuzz-network-action")
          .newTerminalsConnectionAction()
          .withNetworkElement(newString)
          .withActionType(newAction)
          .add()
          .add();

      // Set parameters
      RaoParameters raoParameters = new RaoParameters();
      LoadFlowParameters loadFlowParameters = new LoadFlowParameters();
      loadFlowParameters.setDc(isDc);
      SensitivityAnalysisParameters sensitivityAnalysisParameters =
          new SensitivityAnalysisParameters();
      sensitivityAnalysisParameters.setLoadFlowParameters(loadFlowParameters);

      RaoInput.RaoInputBuilder raoInputBuilder = RaoInput.build(network, crac);
      Rao.find().run(raoInputBuilder.build(), raoParameters);
    } catch (PowsyblException | IllegalArgumentException | IOException e) {
      // Ignore known exceptions
    }
  }
}
