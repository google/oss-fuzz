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
import com.google.common.collect.Range;
import com.powsybl.commons.PowsyblException;
import com.powsybl.commons.datasource.DataSource;
import com.powsybl.commons.datasource.DataSourceUtil;
import com.powsybl.computation.ComputationManager;
import com.powsybl.computation.local.LocalComputationManager;
import com.powsybl.contingency.ContingenciesProvider;
import com.powsybl.contingency.dsl.GroovyDslContingenciesProvider;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.serde.NetworkSerDe;
import com.powsybl.metrix.integration.DefaultNetworkSourceImpl;
import com.powsybl.metrix.integration.Metrix;
import com.powsybl.metrix.integration.MetrixAppLogger;
import com.powsybl.metrix.integration.MetrixRunParameters;
import com.powsybl.metrix.integration.NetworkSource;
import com.powsybl.metrix.integration.io.ResultListener;
import com.powsybl.metrix.integration.metrix.MetrixAnalysis;
import com.powsybl.metrix.integration.metrix.MetrixAnalysisResult;
import com.powsybl.metrix.mapping.ComputationRange;
import com.powsybl.metrix.mapping.DataTableStore;
import com.powsybl.metrix.mapping.EquipmentGroupTimeSeriesWriterObserver;
import com.powsybl.metrix.mapping.EquipmentTimeSeriesWriterObserver;
import com.powsybl.metrix.mapping.MappingParameters;
import com.powsybl.metrix.mapping.NetworkPointWriter;
import com.powsybl.metrix.mapping.TimeSeriesDslLoader;
import com.powsybl.metrix.mapping.TimeSeriesMapper;
import com.powsybl.metrix.mapping.TimeSeriesMapperObserver;
import com.powsybl.metrix.mapping.TimeSeriesMapperParameters;
import com.powsybl.metrix.mapping.TimeSeriesMappingConfig;
import com.powsybl.metrix.mapping.TimeSeriesMappingConfigCsvWriter;
import com.powsybl.metrix.mapping.TimeSeriesMappingConfigTableLoader;
import com.powsybl.metrix.mapping.TimeSeriesMappingLogger;
import com.powsybl.metrix.mapping.timeseries.FileSystemTimeSeriesStore;
import com.powsybl.metrix.mapping.timeseries.InMemoryTimeSeriesStore;
import com.powsybl.timeseries.TimeSeries;
import com.powsybl.timeseries.TimeSeriesIndex;
import com.powsybl.tools.ToolRunningContext;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.NavigableSet;
import java.util.TreeSet;
import java.util.zip.ZipOutputStream;

public class MetrixFuzzer {
  private static Path timeFilePath;
  private static Path mappingFilePath;
  private static Path networkFilePath;
  private static Path contingencyFilePath;
  private static Path configFilePath;
  private static Path actionFilePath;
  private static Path outputFilePath;
  private static Path tempDirPath;

  public static void fuzzerInitialize() {
    try {
      timeFilePath = Files.createTempFile("fuzz-", "-fuzz");
      timeFilePath.toFile().deleteOnExit();
      mappingFilePath = Files.createTempFile("fuzz-", "-fuzz");
      mappingFilePath.toFile().deleteOnExit();
      networkFilePath = Files.createTempFile("fuzz-", "-fuzz");
      networkFilePath.toFile().deleteOnExit();
      contingencyFilePath = Files.createTempFile("fuzz-", "-fuzz");
      contingencyFilePath.toFile().deleteOnExit();
      configFilePath = Files.createTempFile("fuzz-", "-fuzz");
      configFilePath.toFile().deleteOnExit();
      actionFilePath = Files.createTempFile("fuzz-", "-fuzz");
      actionFilePath.toFile().deleteOnExit();
      outputFilePath = Files.createTempFile("fuzz-", "-fuzz");
      outputFilePath.toFile().deleteOnExit();
      tempDirPath = Files.createTempDirectory("fuzz-");
      tempDirPath.toFile().deleteOnExit();
    } catch (Throwable ignored) {
      timeFilePath = null;
      mappingFilePath = null;
      networkFilePath = null;
      outputFilePath = null;
      tempDirPath = null;
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) throws IOException {
    if (tempDirPath == null) {
      return;
    }

    try {
      // Get random values
      int firstVariant = data.consumeInt();
      int maxVariantCount = data.consumeInt();
      int variantCount = data.consumeInt();
      int chunkSize = data.consumeInt();

      // Get random versions in TreeSet
      TreeSet<Integer> versions = new TreeSet<Integer>();
      versions.add(data.consumeInt());

      // Randomise file content
      FileWriter fw = new FileWriter(timeFilePath.toFile());
      fw.write("Time;Version;ts1;ts2\n");
      Long minTs = ZonedDateTime.of(2000, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC).toEpochSecond();
      for (Integer i = 1; i <= data.consumeInt(2, 5); i++) {
        // Safe range for instance epoch second
        Long ts = data.consumeLong(minTs, 32503680000L);
        ZonedDateTime zdt = Instant.ofEpochSecond(ts + i).atZone(ZoneOffset.UTC);
        fw.write(zdt.toString() + ";1;" + ((double) i) + ";" + (i + 0.1) + "\n");
      }
      fw.close();
      fw = new FileWriter(mappingFilePath.toFile());
      fw.write(data.consumeString(data.remainingBytes() / 5));
      fw.close();
      fw = new FileWriter(configFilePath.toFile());
      fw.write(data.consumeString(data.remainingBytes() / 4));
      fw.close();
      fw = new FileWriter(actionFilePath.toFile());
      fw.write(data.consumeString(data.remainingBytes() / 3));
      fw.close();
      fw = new FileWriter(contingencyFilePath.toFile());
      fw.write(data.consumeString(data.remainingBytes() / 2));
      fw.close();
      fw = new FileWriter(networkFilePath.toFile());
      fw.write(data.consumeRemainingAsString());
      fw.close();

      // Prepare different objects from random files
      ZipOutputStream logArchive =
          new ZipOutputStream(new FileOutputStream(outputFilePath.toFile()));
      PrintStream outputStream = new PrintStream(outputFilePath.toFile());
      ComputationManager computationManager = LocalComputationManager.getDefault();
      ToolRunningContext context =
          new ToolRunningContext(
              outputStream,
              outputStream,
              FileSystems.getDefault(),
              computationManager,
              computationManager);

      InMemoryTimeSeriesStore store = new InMemoryTimeSeriesStore();
      store.importTimeSeries(Collections.singletonList(timeFilePath));

      Network network =
          NetworkSerDe.read(
              Object.class.getResourceAsStream(networkFilePath.getFileName().toString()));
      NetworkSource networkSource =
          new DefaultNetworkSourceImpl(networkFilePath, computationManager);

      ContingenciesProvider contingenciesProvider =
          new GroovyDslContingenciesProvider(contingencyFilePath);

      Reader metrixDslReader = Files.newBufferedReader(configFilePath, StandardCharsets.UTF_8);
      Reader remedialActionsReader =
          Files.newBufferedReader(actionFilePath, StandardCharsets.UTF_8);

      MappingParameters mappingParameters = MappingParameters.load();
      ComputationRange computationRange =
          new ComputationRange(store.getTimeSeriesDataVersions(), firstVariant, maxVariantCount);

      TimeSeriesMappingConfig config = null;
      TimeSeriesDslLoader dslLoader = null;
      try (Reader reader = Files.newBufferedReader(mappingFilePath, StandardCharsets.UTF_8)) {
        dslLoader = new TimeSeriesDslLoader(reader, mappingFilePath.getFileName().toString());
        config =
            dslLoader.load(
                network, mappingParameters, store, new DataTableStore(), computationRange);
      }

      TimeSeriesMappingConfigCsvWriter csvWriter =
          new TimeSeriesMappingConfigCsvWriter(
              config, network, store, computationRange, mappingParameters.getWithTimeSeriesStats());
      csvWriter.writeMappingCsv(outputFilePath);

      TimeSeriesMappingLogger logger = new TimeSeriesMappingLogger();
      List<TimeSeriesMapperObserver> observers = new ArrayList<>();

      FileSystemTimeSeriesStore resultStore = new FileSystemTimeSeriesStore(tempDirPath);
      DataSource dataSource = DataSourceUtil.createDataSource(tempDirPath, null);
      observers.add(new NetworkPointWriter(network, dataSource));

      TimeSeriesIndex index =
          new TimeSeriesMappingConfigTableLoader(config, store).checkIndexUnicity();
      int lastPoint = Math.min(firstVariant + maxVariantCount, index.getPointCount()) - 1;
      Range<Integer> range = Range.closed(firstVariant, lastPoint);
      observers.add(
          new EquipmentTimeSeriesWriterObserver(
              network, config, maxVariantCount, range, tempDirPath));
      observers.add(
          new EquipmentGroupTimeSeriesWriterObserver(
              network, config, maxVariantCount, range, tempDirPath));

      TimeSeriesMapperParameters parameters =
          new TimeSeriesMapperParameters(
              (NavigableSet<Integer>) store.getTimeSeriesDataVersions(),
              range,
              true,
              true,
              false,
              mappingParameters.getToleranceThreshold());

      ResultListener listener =
          new ResultListener() {
            @Override
            public void onChunkResult(
                int version, int chunk, List<TimeSeries> timeSeriesList, Network networkPoint) {
              resultStore.importTimeSeries(timeSeriesList, version);
            }

            @Override
            public void onEnd() {
              // Do nothing
            }
          };

      MetrixAppLogger metrixLogger =
          new MetrixAppLogger() {
            @Override
            public void log(String message, Object... args) {
              // Do nothing
            }

            @Override
            public MetrixAppLogger tagged(String tag) {
              return this;
            }
          };

      MetrixAnalysis metrixAnalysis =
          new MetrixAnalysis(
              networkSource,
              dslLoader,
              metrixDslReader,
              remedialActionsReader,
              contingenciesProvider,
              store,
              new DataTableStore(),
              metrixLogger,
              computationRange);
      MetrixAnalysisResult analysisResult = metrixAnalysis.runAnalysis("extern tool");

      // Fuzz mapper
      TimeSeriesMapper mapper = new TimeSeriesMapper(config, parameters, network, logger);
      mapper.mapToNetwork(store, observers);

      // Fuzz Metrix
      Metrix metrix =
          new Metrix(
              remedialActionsReader,
              store,
              resultStore,
              logArchive,
              context,
              metrixLogger,
              analysisResult);
      MetrixRunParameters runParams =
          new MetrixRunParameters(computationRange, chunkSize, true, true, false, false, false);
      metrix.run(runParams, listener, "Fuzz");
    } catch (PowsyblException | IllegalArgumentException | IllegalStateException | IOException e) {
      // Ignore known exceptions
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
