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
////////////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.commons.io.file.PathUtils;

/** This fuzzer targets the static methods of the PathUtils class in the file package. */
public class PathUtilsFuzzer {
  private static Path srcPath;
  private static Path dstPath;
  private static Path file;

  public static void fuzzerInitialize() {
    try {
      srcPath = Files.createTempDirectory("OSS-Fuzz-");
      dstPath = Files.createTempDirectory("OSS-Fuzz-");
      file = Files.createTempFile(srcPath, "OSS-Fuzz-", "-OSS-Fuzz");
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTearDown() {
    try {
      Files.deleteIfExists(srcPath);
      Files.deleteIfExists(dstPath);
      Files.deleteIfExists(file);
    } catch (IOException e) {
      // Known exception
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomize file content
      FileWriter writer = new FileWriter(file.toFile());
      writer.write(data.consumeString(data.remainingBytes()));
      writer.close();

      switch (data.consumeInt(1, 8)) {
        case 1:
          PathUtils.cleanDirectory(dstPath);
          break;
        case 2:
          PathUtils.copyDirectory(srcPath, dstPath);
          break;
        case 3:
          PathUtils.copyFileToDirectory(file, dstPath);
          break;
        case 4:
          PathUtils.countDirectory(dstPath);
          break;
        case 5:
          PathUtils.createParentDirectories(dstPath);
          break;
        case 6:
          PathUtils.directoryAndFileContentEquals(srcPath, dstPath);
          break;
        case 7:
          PathUtils.directoryContentEquals(srcPath, dstPath);
          break;
        case 8:
          PathUtils.fileContentEquals(srcPath, dstPath);
          break;
      }
    } catch (IOException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
