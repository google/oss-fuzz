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
import com.puppycrawl.tools.checkstyle.JavaParser;
import com.puppycrawl.tools.checkstyle.api.CheckstyleException;
import com.puppycrawl.tools.checkstyle.api.FileContents;
import com.puppycrawl.tools.checkstyle.api.FileText;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

// jvm-autofuzz-heuristics-1
public class CheckstyleFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    // Heuristic name: jvm-autofuzz-heuristics-1
    Path path = null;
    try {
      path = Files.createTempFile("oss-fuzz.", ".oss-fuzz");
      Files.write(path, data.consumeRemainingAsBytes());
      FileContents content = new FileContents(new FileText(path.toFile(), "UTF-8"));

      JavaParser.parse(content);
    } catch (IOException | CheckstyleException | NoClassDefFoundError e) {
      // Known exception
    } finally {
      if (path != null) {
        try {
          Files.deleteIfExists(path);
        } catch (IOException e) {
          // Known Exception
        }
      }
    }
  }
}
