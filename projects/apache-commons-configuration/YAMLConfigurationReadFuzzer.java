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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.configuration2.YAMLConfiguration;
import org.apache.commons.configuration2.ex.ConfigurationException;
import org.yaml.snakeyaml.LoaderOptions;

public class YAMLConfigurationReadFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // Create helper objects from fuzzer data
        final boolean useLoaderOptions = data.consumeBoolean();

        // Create needed objects
        final YAMLConfiguration yamlConfig = new YAMLConfiguration();
        yamlConfig.setLogger(null); // disable logging

        // the actual fuzzing starts here
        try {
            if (useLoaderOptions) {
                final LoaderOptions loaderOptions = createLoaderOptions(data);
                yamlConfig.read(new ByteArrayInputStream(data.consumeBytes(Integer.MAX_VALUE)), loaderOptions);
            } else {
                yamlConfig.read(new ByteArrayInputStream(data.consumeBytes(Integer.MAX_VALUE)));
            }
        } catch (ConfigurationException ignored) {
            // expected Exceptions get ignored
        }
    }

    private static LoaderOptions createLoaderOptions(FuzzedDataProvider data) {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setAllowDuplicateKeys(data.consumeBoolean());
        loaderOptions.setWrappedToRootException(data.consumeBoolean());
        loaderOptions.setAllowRecursiveKeys(data.consumeBoolean());
        loaderOptions.setProcessComments(data.consumeBoolean());
        loaderOptions.setEnumCaseSensitive(data.consumeBoolean());

        return loaderOptions;
    }
}
