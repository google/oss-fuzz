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

import java.util.List;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayInputStream;
import java.io.UncheckedIOException;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;

public class CSVParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    CSVFormat[] formats = { CSVFormat.DEFAULT,
                            CSVFormat.DEFAULT.withHeader(),
                            CSVFormat.EXCEL, 
                            CSVFormat.EXCEL.withHeader(), 
                            CSVFormat.INFORMIX_UNLOAD, 
                            CSVFormat.INFORMIX_UNLOAD.withHeader(), 
                            CSVFormat.INFORMIX_UNLOAD_CSV, 
                            CSVFormat.INFORMIX_UNLOAD_CSV.withHeader(), 
                            CSVFormat.MYSQL, 
                            CSVFormat.MYSQL.withHeader(), 
                            CSVFormat.RFC4180, 
                            CSVFormat.RFC4180.withHeader(), 
                            CSVFormat.ORACLE, 
                            CSVFormat.ORACLE.withHeader(), 
                            CSVFormat.POSTGRESQL_CSV, 
                            CSVFormat.POSTGRESQL_CSV.withHeader(), 
                            CSVFormat.POSTGRESQL_TEXT, 
                            CSVFormat.POSTGRESQL_TEXT.withHeader(), 
                            CSVFormat.TDF, 
                            CSVFormat.TDF.withHeader() 
                          };
    ByteArrayInputStream bais = new ByteArrayInputStream(data.consumeRemainingAsBytes());
    CSVFormat format = data.pickValue(formats);
    try{
      CSVParser parser = CSVParser.parse(bais, StandardCharsets.UTF_8, format);
      List<CSVRecord> records = parser.getRecords();
    }
    catch( IOException | java.io.UncheckedIOException e ){
      return;
    }
  }
}
