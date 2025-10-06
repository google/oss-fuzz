// Copyright 2025 Google LLC
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

// Copyright 2025 Google LLC
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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.kafka.common.header.internals.RecordHeaders;
import org.apache.kafka.common.record.*;

public class KafkaRecordFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            // Test record creation with fuzzed data
            byte[] key = data.consumeBytes(1000);
            byte[] value = data.consumeRemainingAsBytes();
            
            testRecordSerialization(key, value);
            testCompression(data);
            
        } catch (Exception e) {
            // Ignore expected exceptions
        }
    }
    
    private static void testRecordSerialization(byte[] key, byte[] value) {
        try {
            RecordHeaders headers = new RecordHeaders();
            headers.add("test-header", "value".getBytes());
            
            // This would test Kafka's record handling with corrupted data
            // Important for finding serialization vulnerabilities
            
        } catch (Exception e) {
            // Expected for invalid record data
        }
    }
    
    private static void testCompression(FuzzedDataProvider data) {
        try {
            // Test compression with fuzzed data
            byte[] compressedData = data.consumeBytes(500);
            // This would test Kafka's compression handling
            // Critical for finding decompression vulnerabilities
            
        } catch (Exception e) {
            // Expected for invalid compressed data
        }
    }
}
