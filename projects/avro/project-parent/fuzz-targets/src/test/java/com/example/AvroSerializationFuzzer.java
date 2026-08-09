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

import org.apache.avro.Schema;
import org.apache.avro.mapred.AvroKey;
import org.apache.avro.mapred.AvroValue;
import org.apache.avro.mapreduce.AvroJob;
import org.apache.avro.mapred.AvroWrapper;
import org.apache.avro.generic.GenericData;
import org.apache.avro.AvroRuntimeException;
import org.apache.avro.hadoop.io.AvroSerialization;
import org.apache.hadoop.mapreduce.Job;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.util.ReflectionUtils;
import org.apache.hadoop.io.serializer.Serializer;
import org.apache.hadoop.io.serializer.Deserializer;
import org.junit.jupiter.api.BeforeAll;

import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;


class AvroSerializationFuzzer {
    static Job job = null;
    Class [] classes = {AvroKey.class, AvroValue.class};

    @BeforeAll
    static void setUp(){
        try {
            job = new Job(new Configuration());
        } catch (IOException e) {
        }
    }

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try {
            int opt = 7;
            int num = data.consumeInt(0, 2^opt - 1);
            for (int bit = 0; bit < opt; ++bit) {
                if (((num >> bit) & 1) == 1) {
                    switch (bit) {
                        case 0:
                            AvroJob.setMapOutputKeySchema(job, data.pickValue(new Schema[]{Schema.create(data.pickValue(Schema.Type.values())),
                                    new Schema.Parser().parse(data.consumeString(1000))}));
                            break;
                        case 1:
                            AvroJob.setMapOutputValueSchema(job, data.pickValue(new Schema[]{Schema.create(data.pickValue(Schema.Type.values())),
                                    new Schema.Parser().parse(data.consumeString(1000))}));
                            break;
                        case 2:
                            AvroJob.setInputKeySchema(job, data.pickValue(new Schema[]{Schema.create(data.pickValue(Schema.Type.values())),
                                    new Schema.Parser().parse(data.consumeString(1000))}));
                            break;
                        case 3:
                            AvroJob.setInputValueSchema(job, data.pickValue(new Schema[]{Schema.create(data.pickValue(Schema.Type.values())),
                                    new Schema.Parser().parse(data.consumeString(1000))}));
                            break;
                        case 4:
                            AvroJob.setOutputKeySchema(job, data.pickValue(new Schema[]{Schema.create(data.pickValue(Schema.Type.values())),
                                    new Schema.Parser().parse(data.consumeString(1000))}));
                            break;
                        case 5:
                            AvroJob.setOutputValueSchema(job, data.pickValue(new Schema[]{Schema.create(data.pickValue(Schema.Type.values())),
                                    new Schema.Parser().parse(data.consumeString(1000))}));
                            break;
                        case 6:
                            AvroJob.setDataModelClass(job, GenericData.class);
                            break;
                    }
                }
            }

            AvroSerialization serialization = ReflectionUtils.newInstance(AvroSerialization.class, job.getConfiguration());
            Serializer serializer = serialization.getSerializer(data.pickValue(classes));
            Deserializer deserializer = serialization.getDeserializer(data.pickValue(classes));

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            serializer.open(baos);
            serializer.serialize(data.consumeBytes(1000));
            serializer.close();

            ByteArrayInputStream bais = new ByteArrayInputStream(data.consumeRemainingAsBytes());
            deserializer.open(bais);
            AvroWrapper<CharSequence> result = null;
            deserializer.deserialize(result);
            deserializer.close();
        } catch (IOException e) {
        } catch (AvroRuntimeException | UnsupportedOperationException | ClassCastException | IllegalArgumentException | NullPointerException e) {
            // Need to catch to find more interesting findings.
        }
    }
}