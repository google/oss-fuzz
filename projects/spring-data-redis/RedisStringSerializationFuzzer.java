// Copyright 2022 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.springframework.data.redis.serializer.StringRedisSerializer;


public class RedisStringSerializationFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int value = data.consumeInt(0,2);
        String original_input = data.consumeRemainingAsString();
        String deserialized_input = null;
        byte[] serialized_input = null;
        String format = null;
        switch (value) {
            case 0:
                format = "US_ASCII";
                serialized_input = StringRedisSerializer.US_ASCII.serialize(original_input);
                deserialized_input = StringRedisSerializer.US_ASCII.deserialize(serialized_input);
            case 1:
                format = "ISO_8859_1";
                serialized_input = StringRedisSerializer.ISO_8859_1.serialize(original_input);
                deserialized_input = StringRedisSerializer.ISO_8859_1.deserialize(serialized_input);
            case 2:
                format = "UTF_8";
                serialized_input = StringRedisSerializer.UTF_8.serialize(original_input);
                deserialized_input = StringRedisSerializer.UTF_8.deserialize(serialized_input);
        }
        if (!deserialized_input.equals(original_input)) {
            throw new IllegalStateException("Failed to recover\n" + original_input + "\ndeserialized with " + format 
                    + ", got:\n" + deserialized_input + "\n\n");
        }
    }
}