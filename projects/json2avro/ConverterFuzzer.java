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

import org.apache.avro.Schema;
import tech.allegro.schema.json2avro.converter.AvroConversionException;
import tech.allegro.schema.json2avro.converter.JsonAvroConverter;

// jvm-autofuzz-heuristics-2
public class ConverterFuzzer {
  private static final String schemaStr = "{\"type\" : \"record\"," +
                        "\"name\" : \"name\"," +
                        "\"fields\" : [" +
                        "{\"name\" : \"name1\", \"type\" : [\"null\", \"string\"], \"default\": null}," +
                        "{\"name\" : \"name2\", \"type\" : [\"null\", \"int\"], \"default\": null}" +
                        "]}";

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
  // Heuristic name: jvm-autofuzz-heuristics-2
    Schema schema = new Schema.Parser().parse(schemaStr);
    try {
      new JsonAvroConverter().convertToGenericDataRecord(data.consumeRemainingAsBytes(), schema);
    } catch (AvroConversionException e) {
      // Known exception
    }
  }
}
