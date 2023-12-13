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
import java.time.LocalDate;
import org.apache.commons.io.FileUtils;

/** This fuzzer targets the static methods of the File related Utils class in the base package. */
public class FileUtilsFuzzer {
  private static final String PREFIX = "OSS-Fuzz";
  private static Path srcPath;
  private static Path dstPath;
  private static Path srcFile;
  private static Path dstFile;

  public static void fuzzerInitialize() {
    try {
      srcPath = Files.createTempDirectory(PREFIX);
      dstPath = Files.createTempDirectory(PREFIX);
      srcFile = Files.createTempFile(srcPath, PREFIX, PREFIX);
      dstFile = Files.createTempFile(dstPath, PREFIX, PREFIX);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static void fuzzerTearDown() {
    try {
      Files.deleteIfExists(srcFile);
      Files.deleteIfExists(dstFile);
      Files.deleteIfExists(srcPath);
      Files.deleteIfExists(dstPath);
    } catch (IOException e) {
      // Known exception
    }
  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Randomize file content
      FileWriter writer = new FileWriter(srcFile.toFile());
      writer.write(data.consumeString(data.remainingBytes()));
      writer.close();

      switch (data.consumeInt(1, 16)) {
        case 1:
          FileUtils.byteCountToDisplaySize(data.consumeLong());
          break;
        case 2:
          FileUtils.checksumCRC32(srcFile.toFile());
          break;
        case 3:
          FileUtils.contentEquals(srcFile.toFile(), dstFile.toFile());
          break;
        case 4:
          FileUtils.contentEqualsIgnoreEOL(srcFile.toFile(), dstFile.toFile(), null);
          break;
        case 5:
          FileUtils.copyDirectoryToDirectory(srcPath.toFile(), dstPath.toFile());
          break;
        case 6:
          FileUtils.copyFile(srcFile.toFile(), dstFile.toFile());
          break;
        case 7:
          FileUtils.copyFileToDirectory(srcFile.toFile(), dstPath.toFile());
          break;
        case 8:
          FileUtils.copyToDirectory(srcFile.toFile(), dstPath.toFile());
          break;
        case 9:
          FileUtils.isFileNewer(dstFile.toFile(), LocalDate.now());
          break;
        case 10:
          FileUtils.isFileOlder(dstFile.toFile(), LocalDate.now());
          break;
        case 11:
          FileUtils.lastModified(srcFile.toFile());
          break;
        case 12:
          FileUtils.lineIterator(srcFile.toFile());
          break;
        case 13:
          FileUtils.moveFile(srcFile.toFile(), dstFile.toFile());
          break;
        case 14:
          FileUtils.streamFiles(srcPath.toFile(), true, null);
          break;
        case 15:
          FileUtils.toFiles(srcFile.toUri().toURL());
          break;
        case 16:
          FileUtils.toURLs(srcFile.toFile());
          break;
      }
    } catch (IOException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
