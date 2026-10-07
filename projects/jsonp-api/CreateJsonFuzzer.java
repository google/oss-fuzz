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
import jakarta.json.stream.JsonParsingException;
import java.io.PrintStream;
import java.io.OutputStream;

public class CreateJsonFuzzer {
    private static final PrintStream noopStream = new PrintStream(new OutputStream() {
        @Override
        public void write(int b) {}
    });

    public static void fuzzerInitialize() {
        System.setErr(noopStream);
        System.setOut(noopStream);
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            testJsonCreators(data);
            JsonValue.ValueType.valueOf(data.consumeString(100));
        } catch (IllegalArgumentException | JsonParsingException e) {}
    }

    public static void testJsonCreators(FuzzedDataProvider data) {
        JsonArray jsonArray = JSONP_Util.createJsonArrayFromString(data.consumeString(200));
        JSONP_Util.toStringJsonArray(jsonArray);

        JsonObject jsonObject = JSONP_Util.createJsonObjectFromString(data.consumeString(200));
        JSONP_Util.toStringJsonObject(jsonObject);

        String inStr = data.consumeAsciiString(200);
        JsonString jsonString = JSONP_Util.createJsonString(inStr);
        String outString = JSONP_Util.toStringJsonString(jsonString);
        String intJsonStr = "\"" + inStr + "\"";
        if (!intJsonStr.equals(outString)) {
            throw new FuzzerSecurityIssueLow("JsonString: " + intJsonStr + " Expected. Got " + outString);
        }

        int inNumber = data.consumeInt();
        JsonNumber jsonNumber = JSONP_Util.createJsonNumber(inNumber);
        String outNumber = JSONP_Util.toStringJsonNumber(jsonNumber);
        if (!Integer.toString(inNumber).equals(outNumber)) {
            throw new FuzzerSecurityIssueLow("JsonNumber: " + inNumber + " Expected. Got " + outNumber);
        }
    }
}
