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

import com.amazon.ion.*;
import com.amazon.ion.system.IonReaderBuilder;

import java.io.IOException;


class IonReaderFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try {
            IonReader reader = IonReaderBuilder
                                .standard()
                                .withAnnotationIteratorReuseEnabled(data.consumeBoolean())
                                .withIncrementalReadingEnabled(data.consumeBoolean())
                                .build(data.consumeRemainingAsString());
            read(reader);
            reader.close();
        } catch (IOException | NullPointerException | IllegalStateException | IllegalArgumentException | ArrayIndexOutOfBoundsException | IonException | AssertionError e) {
            // Need to be caught to get more interesting findings.
        }
    }

    void read(IonReader reader) {
        reader.next();
        reader.stepIn();
        reader.next();
        reader.getFieldName();
        reader.stringValue();
        reader.stepOut();
    }
}