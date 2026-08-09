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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.serde.serdeConstants;
import org.apache.hadoop.hive.serde2.JsonSerDe;
import org.apache.hadoop.hive.serde2.OpenCSVSerde;
import org.apache.hadoop.hive.serde2.SerDeException;
import org.apache.hadoop.hive.serde2.columnar.ColumnarSerDe;
import org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe;
import org.apache.hadoop.hive.serde2.lazybinary.LazyBinarySerDe;
import org.apache.hadoop.io.Text;

import java.util.Properties;


class DeserializeFuzzer {

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        JsonSerDe json = new JsonSerDe();
        OpenCSVSerde csv = new OpenCSVSerde();
        LazySimpleSerDe ls = new LazySimpleSerDe();
        LazyBinarySerDe lb = new LazyBinarySerDe();
        ColumnarSerDe col = null;
        try {
            col = new ColumnarSerDe();
        } catch (SerDeException expected) {
        }

        Properties props = new Properties();
        props.setProperty(serdeConstants.LIST_COLUMNS, data.consumeString(1000));
        props.setProperty(serdeConstants.LIST_COLUMN_TYPES, data.consumeString(1000));
        Text input = new Text(data.consumeRemainingAsString());

        try {
            json.initialize(new Configuration(), props, null, false);
            json.deserialize(input);
        } catch (SerDeException expected) {
        } catch (RuntimeException ignored) {
        }

        try {
            csv.initialize(new Configuration(), props, null);
            csv.deserialize(input);
        } catch (SerDeException expected) {
        } catch (RuntimeException ignored) {
        }

        try {
            ls.initialize(new Configuration(), props, null);
            ls.deserialize(input);
        } catch (SerDeException expected) {
        } catch (RuntimeException ignored) {
        }

        try {
            lb.initialize(new Configuration(), props, null);
            lb.deserialize(input);
        } catch (SerDeException expected) {
        } catch (RuntimeException ignored) {
        }

        try {
            col.initialize(new Configuration(), props, null);
            col.deserialize(input);
        } catch (SerDeException expected) {
        } catch (RuntimeException ignored) {
        }
    }
}