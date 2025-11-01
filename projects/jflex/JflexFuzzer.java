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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import jflex.exceptions.GeneratorException;
import jflex.generator.LexGenerator;
import jflex.logging.Out;

public class JflexFuzzer {
  private static File tempDirectory;
  private static File tempFile;

  public static void fuzzerInitialize() {
    try {
      tempDirectory = Files.createTempDirectory("oss-fuzz").toFile().getAbsoluteFile();
      tempFile = new File(tempDirectory + "/"
          + "oss-fuzz-temp.java");
    } catch (IOException e) {
      // Known exception
    }
  }

  public static void fuzzerTearDown() {
    tempFile.delete();
    tempDirectory.delete();
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Discard all log message
      Out.setOutputStream(OutputStream.nullOutputStream());

      PrintWriter printWriter = new PrintWriter(new FileWriter(tempFile));
      printWriter.print("%%" + data.consumeRemainingAsString());
      printWriter.close();

      LexGenerator generator = new LexGenerator(tempFile);
      generator.generate();
    } catch (GeneratorException | IOException e) {
      // Known exception
    }
  }
}
