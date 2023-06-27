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

import org.apache.hadoop.io.serializer.*;
import org.apache.hadoop.io.DataInputBuffer;
import org.apache.hadoop.io.DataOutputBuffer;

import java.io.IOException;


class JavaSerializationFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        String s = data.consumeString(5000);
        String d = data.consumeRemainingAsString();

        Serialization ser = new JavaSerialization();
        try {
            Serializer<String> serializer = ser.getSerializer(String.class);
            DataOutputBuffer dob = new DataOutputBuffer();
            serializer.open(dob);
            serializer.serialize(s);
            serializer.close();

            Deserializer<String> deserializer = ser.getDeserializer(String.class);
            DataInputBuffer dib = new DataInputBuffer();
            dib.reset(d.getBytes(), d.length());
            deserializer.open(dib);
            deserializer.deserialize(null);
            deserializer.close();
        } catch (IOException e) {
        } catch (ClassCastException | ArrayIndexOutOfBoundsException | NegativeArraySizeException | NullPointerException e) {
            // Need to catch in order to find more interesting findings.
        }
    }
}