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
import com.code_intelligence.jazzer.junit.FuzzTest;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class JsonParserFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        JSONParser parser = new JSONParser();
        try {
            JSONObject jsonObj = (JSONObject)parser.parse(data.consumeRemainingAsString());
        }

        // ParseExeception is expected when JSON is invalid
        // ClassCastException occurs when parser returns primitive
        // NumberFormatException occurs when input at root level exceeds long size
        catch (ParseException | ClassCastException | NumberFormatException e) {

        }
    }
}