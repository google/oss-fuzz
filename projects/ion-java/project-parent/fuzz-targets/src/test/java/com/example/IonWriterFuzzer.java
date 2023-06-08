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

import com.amazon.ion.system.IonBinaryWriterBuilder;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

import com.amazon.ion.*;
import com.amazon.ion.system.IonReaderBuilder;
import com.amazon.ion.system.IonTextWriterBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.Charset;

import static com.amazon.ion.system.IonTextWriterBuilder.ASCII;
import static com.amazon.ion.system.IonTextWriterBuilder.UTF8;


class IonWriterFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        int cn = 15;
        int dummyNum = data.consumeInt(0, 2^cn - 1);
        IonTextWriterBuilder ionTextWriterBuilder = null;
        IonBinaryWriterBuilder ionBinaryWriterBuilder = null;

        try {
            for (int bit = 0; bit < cn; ++bit) {
                if (((dummyNum >> bit) & 1) == 1) {
                    switch (bit) {
                        case 0:
                            ionTextWriterBuilder = ionTextWriterBuilder.json();
                            break;
                        case 1:
                            ionTextWriterBuilder = ionTextWriterBuilder.minimal();
                            break;
                        case 2:
                            ionTextWriterBuilder = ionTextWriterBuilder.pretty();
                            break;
                        case 3:
                            ionTextWriterBuilder = ionTextWriterBuilder.standard();
                            break;
                        case 4:
                            ionTextWriterBuilder = ionTextWriterBuilder.withCharset(data.pickValue(new Charset[] {ASCII, UTF8}));
                            break;
                        case 5:
                            ionTextWriterBuilder = ionTextWriterBuilder.withJsonDowngrade();
                            break;
                        case 6:
                            ionTextWriterBuilder = ionTextWriterBuilder.withMinimalSystemData();
                            break;
                        case 7:
                            ionTextWriterBuilder = ionTextWriterBuilder.withPrettyPrinting();
                            break;
                        case 8:
                            ionTextWriterBuilder = ionTextWriterBuilder.withWriteTopLevelValuesOnNewLines(data.consumeBoolean());
                            break;
                        case 9:
                            ionBinaryWriterBuilder = ionBinaryWriterBuilder.standard();
                            break;
                        case 10:
                            ionBinaryWriterBuilder = ionBinaryWriterBuilder.withFloatBinary32Disabled();
                            break;
                        case 11:
                            ionBinaryWriterBuilder = ionBinaryWriterBuilder.withFloatBinary32Enabled();
                            break;
                        case 12:
                            ionBinaryWriterBuilder = ionBinaryWriterBuilder.withLocalSymbolTableAppendDisabled();
                            break;
                        case 13:
                            ionBinaryWriterBuilder = ionBinaryWriterBuilder.withLocalSymbolTableAppendEnabled();
                            break;
                        case 14:
                            ionBinaryWriterBuilder = ionBinaryWriterBuilder.withStreamCopyOptimized(data.consumeBoolean());
                            break;
                    }
                }
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            String input = data.consumeRemainingAsString();

            IonWriter ionWriter = ionTextWriterBuilder.build(out);
            rewrite(input, ionWriter);
            ionWriter.close();

            ionWriter = ionBinaryWriterBuilder.build(out);
            rewrite(input, ionWriter);
            ionWriter.close();
        } catch (IOException | NullPointerException | IllegalArgumentException | IonException | AssertionError e) {
            // Need to be caught to get more interesting findings.
        }
    }

    void rewrite(String textIon, IonWriter writer) throws IOException {
        try (IonReader reader = IonReaderBuilder.standard().build(textIon)) {
            writer.writeValues(reader);
        }
    }
}