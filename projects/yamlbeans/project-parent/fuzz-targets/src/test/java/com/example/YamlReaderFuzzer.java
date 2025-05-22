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

import com.esotericsoftware.yamlbeans.YamlConfig;
import com.esotericsoftware.yamlbeans.YamlException;
import com.esotericsoftware.yamlbeans.YamlReader;

import java.util.NoSuchElementException;


class YamlReaderFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        YamlConfig yamlConfig = new YamlConfig();
        yamlConfig.setAllowDuplicates(data.consumeBoolean());
        yamlConfig.setBeanProperties(data.consumeBoolean());
        yamlConfig.setPrivateConstructors(data.consumeBoolean());
        yamlConfig.setPrivateFields(data.consumeBoolean());

        YamlReader reader = new YamlReader(data.consumeRemainingAsString(), yamlConfig);

        while (true) {
            Object object = null;
            try {
                object = reader.read();
            } catch (YamlException e) {
            } catch (NoSuchElementException | NullPointerException | IndexOutOfBoundsException e) {
                // Need to catch to let fuzzer continue.
            }
            if (object == null) break;
        }
    }
}