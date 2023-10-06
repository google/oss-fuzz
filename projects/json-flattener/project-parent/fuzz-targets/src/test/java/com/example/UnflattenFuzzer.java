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
import com.github.wnameless.json.unflattener.JsonUnflattener;
import com.github.wnameless.json.unflattener.JsonUnflattenerFactory;

import java.util.function.Consumer;


class UnflattenFuzzer {
    static PrintMode [] printModes = {PrintMode.PRETTY, PrintMode.MINIMAL};
    static FlattenMode [] flattenModes = {FlattenMode.NORMAL, FlattenMode.MONGODB, FlattenMode.KEEP_ARRAYS, FlattenMode.KEEP_PRIMITIVE_ARRAYS};
    static JsonCore [] jsonCores = {new GsonJsonCore(), new JacksonJsonCore()};

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try {
            JsonUnflattenerFactory jsonUnflattenerFactory = jsonUnflattenerFactory(data.pickValue(printModes), data.pickValue(flattenModes), data.pickValue(jsonCores));
            String json = data.consumeRemainingAsString();
            JsonUnflattener ju = jsonUnflattenerFactory.build(json);

            ju.unflatten();
            ju.unflattenAsMap();
        } catch (RuntimeException e) {
            // Need to catch it to let fuzzer find initeresting findings.
        }
    }

    static JsonUnflattenerFactory jsonUnflattenerFactory(PrintMode pm, FlattenMode fm, JsonCore<?> jc) {
        Consumer<JsonUnflattener> configurer = ju -> ju.withPrintMode(pm).withFlattenMode(fm);

        return new JsonUnflattenerFactory(configurer, jc);
    }
}