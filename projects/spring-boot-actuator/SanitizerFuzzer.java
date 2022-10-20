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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;

import org.springframework.boot.actuate.endpoint.Sanitizer;
import org.springframework.boot.actuate.endpoint.SanitizableData;

public class SanitizerFuzzer {

    public static final String SANITIZED_VALUE = "******";

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        boolean sw = data.consumeBoolean();
        String key = data.consumeString(50);
        String value = data.consumeRemainingAsString();

        if (value.isEmpty() || key.isEmpty()) {
            return;
        }

        Sanitizer sanitizer = new Sanitizer();
        SanitizableData custom = new SanitizableData(null, key, value);

        String result = (String) sanitizer.sanitize(custom, sw);
        if (sw) {
            if (result != null & !result.equals(value)) {
                throw new FuzzerSecurityIssueMedium("Value not equal to result. key: " + key + " value:" + value + " result:" + result);
            }
        }
        else {
            if (!result.equals(SANITIZED_VALUE)) {
                throw new FuzzerSecurityIssueMedium("Value not sanitized. result: " + result + " sanitizer: "+SANITIZED_VALUE);
            }
        }
        
    } 
}
