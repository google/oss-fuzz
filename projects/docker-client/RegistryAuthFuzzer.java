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
import com.spotify.docker.client.DockerConfigReader;
import com.spotify.docker.client.messages.RegistryAuth;
import java.io.File;
import java.nio.file.Files;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.io.IOException;
import java.io.PrintWriter;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-6
// Heuristic name: jvm-autofuzz-heuristics-6
// Target method: [com.spotify.docker.client.DockerConfigReader] public com.spotify.docker.client.messages.RegistryAuth fromConfig(java.nio.file.Path,java.lang.String) throws java.io.IOException
public class RegistryAuthFuzzer {
  private static File tempDirectory;
  private static File tempFile;
  public static void fuzzerInitialize() {
    try {
      tempDirectory =
          Files.createTempDirectory("oss-fuzz").toFile().getAbsoluteFile();
      tempFile = new File(tempDirectory, "oss-fuzz-temp").getAbsoluteFile();
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
      PrintWriter printWriter = new PrintWriter(new FileWriter(tempFile));
      printWriter.print(data.consumeString(data.remainingBytes() / 2));
      printWriter.close();
    } catch (IOException e) {
      // Known exception
    }
    try {
      DockerConfigReader obj = new DockerConfigReader();
      obj.fromConfig(tempFile.toPath(), data.consumeRemainingAsString());
    } catch (IOException e1) {
    }
  }
}
