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

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import java.io.*;

public class JsonEncodeDecodeFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            String fuzzingString = data.consumeRemainingAsString();
            JSONObject srcObj = new JSONObject();
            srcObj.put("item1", fuzzingString);
            
            StringWriter out = new StringWriter();
            srcObj.writeJSONString(out);
            String jsonText = out.toString();

            StringReader in = new StringReader(jsonText);
            JSONParser parser = new JSONParser();
            JSONObject destObj = (JSONObject)parser.parse(in);

            if (!destObj.equals(srcObj)) {
                throw new IllegalStateException("Decoded object: "
                 + destObj.toString() + " doesn't match original object: " + srcObj.toString());
            }            
        }
        catch (IOException | ParseException e){

        }
    }
}