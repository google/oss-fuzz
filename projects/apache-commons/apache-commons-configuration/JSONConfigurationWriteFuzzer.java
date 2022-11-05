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

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.io.IOException;

import org.apache.commons.configuration2.JSONConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;

public class JSONConfigurationWriteFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // Create helper objects from fuzzer data
        final boolean useReader = data.consumeBoolean();
        final byte[] byteArray = data.consumeBytes(Integer.MAX_VALUE);

        // Create needed objects
        JSONConfiguration jsonConfig = new JSONConfiguration();
        jsonConfig.setLogger(null); // disable logger

        InputStream inputStream = new ByteArrayInputStream(byteArray);
        InputStreamReader reader;
        StringWriter writer = new StringWriter();

        try {
            if (useReader) {
                reader = new InputStreamReader(inputStream);
                jsonConfig.read(reader);
            } else {
                jsonConfig.read(inputStream);
            }
            jsonConfig.write(writer);
        } catch (IOException | ConfigurationException ignored) {
            // expected Exceptions get ignored
        }
    }
}
