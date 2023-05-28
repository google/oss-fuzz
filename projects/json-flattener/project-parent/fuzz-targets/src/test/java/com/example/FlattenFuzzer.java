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

import com.github.wnameless.json.flattener.*;
import com.github.wnameless.json.base.JsonCore;
import com.github.wnameless.json.base.GsonJsonCore;
import com.github.wnameless.json.base.JacksonJsonCore;

import java.util.function.Consumer;


class FlattenFuzzer {
    static PrintMode [] printModes = {PrintMode.PRETTY, PrintMode.MINIMAL};
    static FlattenMode [] flattenModes = {FlattenMode.NORMAL, FlattenMode.MONGODB, FlattenMode.KEEP_ARRAYS, FlattenMode.KEEP_PRIMITIVE_ARRAYS};
    static StringEscapePolicy [] stringEscapePolicies = {StringEscapePolicy.DEFAULT, StringEscapePolicy.ALL, StringEscapePolicy.ALL_BUT_SLASH, StringEscapePolicy.ALL_BUT_UNICODE, StringEscapePolicy.ALL_BUT_SLASH_AND_UNICODE};
    static JsonCore [] jsonCores = {new GsonJsonCore(), new JacksonJsonCore()};

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {

        try {
            JsonFlattenerFactory jsonFlattenerFactory = jsonFlattenerFactory(data.pickValue(printModes), data.pickValue(flattenModes), data.pickValue(stringEscapePolicies), data.pickValue(jsonCores));
            String json = data.consumeRemainingAsString();
            JsonFlattener jf = jsonFlattenerFactory.build(json);

            jf.flatten();
            jf.flattenAsMap();
        } catch (RuntimeException e) {
            // Need to catch it to let fuzzer find interesting findings.
        }
    }

    static JsonFlattenerFactory jsonFlattenerFactory(PrintMode pm, FlattenMode fm, StringEscapePolicy sep, JsonCore<?> jc) {
        Consumer<JsonFlattener> configurer = jf -> jf.withPrintMode(pm).withFlattenMode(fm).withStringEscapePolicy(sep);

        return new JsonFlattenerFactory(configurer, jc);
    }
}