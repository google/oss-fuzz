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
import com.powsybl.cgmes.conversion.CgmesImport;
import com.powsybl.commons.PowsyblException;
import com.powsybl.commons.datasource.ReadOnlyMemDataSource;
import com.powsybl.iidm.network.Bus;
import com.powsybl.iidm.network.Generator;
import com.powsybl.iidm.network.Importer;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.NetworkFactory;
import com.powsybl.ieeecdf.converter.IeeeCdfImporter;
import com.powsybl.loadflow.LoadFlow;
import com.powsybl.loadflow.LoadFlowParameters;
import com.powsybl.matpower.converter.MatpowerImporter;
import com.powsybl.nad.NetworkAreaDiagram;
import com.powsybl.powerfactory.converter.PowerFactoryImporter;
import com.powsybl.powerfactory.model.PowerFactoryException;
import com.powsybl.psse.converter.PsseImporter;
import com.powsybl.sld.SingleLineDiagram;
import com.powsybl.ucte.converter.UcteImporter;

import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public class ImporterFuzzer {
    private static Path tempFile;

    public static void fuzzerInitialize() {
        try {
            tempFile = Files.createTempFile("fuzz-", "-fuzz");
            tempFile.toFile().deleteOnExit();
        } catch (Throwable ignored) {
            tempFile = null;
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            Importer importer = null;
            int choice = data.consumeInt(1, 6);
            double[] randomDouble = new double[8];

            for (int i = 0; i < randomDouble.length; i++) {
                randomDouble[i] = data.consumeDouble();
            }

            byte[] inputBytes = data.consumeRemainingAsBytes();
            ReadOnlyMemDataSource ds = new ReadOnlyMemDataSource("fuzz");
            ds.putData("fuzz", inputBytes);

            switch (choice) {
                case 1:
                    importer = new CgmesImport();
                    break;
                case 2:
                    importer = new IeeeCdfImporter();
                    break;
                case 3:
                    importer = new MatpowerImporter();
                    break;
                case 4:
                    importer = new PowerFactoryImporter();
                    break;
                case 5:
                    importer = new PsseImporter();
                    break;
                case 6:
                    importer = new UcteImporter();
                    break;
                default:
                    return;
            }

            if (importer != null) {
                Network network = importer.importData(ds, NetworkFactory.findDefault(), new Properties());

                if (network.getBusView().getBuses().spliterator().getExactSizeIfKnown() > 0 && network.getGeneratorCount() > 0) {

                    // Modify buses with random values
                    for (Bus bus : network.getBusView().getBuses()) {
                        bus.setV(Math.abs(randomDouble[0]));
                        bus.setAngle(randomDouble[1]);
                    }

                    // Modify generators with random values
                    for (Generator generator : network.getGenerators()) {
                        generator.setMaxP(Math.abs(randomDouble[2]));
                        generator.setMinP(Math.max(0, randomDouble[3]));
                        generator.setTargetV(randomDouble[4]);
                        generator.setTargetP(randomDouble[5]);
                        generator.setTargetQ(randomDouble[6]);
                        generator.setRatedS(Math.max(1.0, randomDouble[7]));
                    }

                    // Fuzz network load flow
                    LoadFlow.run(network, new LoadFlowParameters());

                    // Fuzz diagram draw
                    if (tempFile != null) {
                        NetworkAreaDiagram.draw(network, tempFile);
                        SingleLineDiagram.draw(network, "fuzz", tempFile);
                    }
                }
            }
        } catch (PowsyblException | UncheckedIOException | PowerFactoryException | IllegalArgumentException e) {
            // Ignore known exceptions
        }
    }
}
