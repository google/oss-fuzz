// Copyright 2024 Google LLC
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

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import de.siegmar.fastcsv.reader.CsvReader;
import de.siegmar.fastcsv.reader.CsvParseException;

public class CsvReaderFuzzer {
  public static void fuzzerTestOneInput(byte[] input) {
    try {
      CsvReader.builder()
        .ofCsvRecord(new InputStreamReader(new ByteArrayInputStream(input), StandardCharsets.UTF_8))
        .stream()
        .toList();
    } catch (CsvParseException e) {
    }
  }
}
