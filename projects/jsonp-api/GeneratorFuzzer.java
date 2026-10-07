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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import ee.jakarta.tck.jsonp.common.JSONP_Util;
import jakarta.json.*;
import jakarta.json.stream.JsonGenerator;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;

public class GeneratorFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        JsonGenerator generator = Json.createGenerator(baos).writeStartObject();

        try {
            for (int i = 0; i < data.consumeInt(0, 10); i++) {
                if (data.consumeBoolean()) {
                    generator.writeStartObject(data.consumeString(20));
                } else {
                    generator.writeStartArray(data.consumeString(20));
                }

                for (int j = 0; j < data.consumeInt(0, 20); j++) {
                    int writeChoice = data.consumeInt(0, 3);
                    switch (writeChoice) {
                        case 0:
                            generator.write(data.consumeString(50), data.consumeInt());
                            break;
                        case 1:
                            generator.write(data.consumeString(50), data.consumeString(50));
                            break;
                        case 2:
                            generator.write(data.consumeString(50), data.consumeBoolean());
                            break;
                        case 3:
                            generator.write(JSONP_Util.createJsonString(data.consumeString(50)));
                            break;
                    }
                }
                generator.writeEnd();
            }

            generator.writeEnd();
            generator.close();
            baos.close();

            JSONP_Util.removeWhitespace(baos.toString("UTF-8"));

        } catch (JsonException | IOException | IllegalArgumentException e) {}
    }
}
