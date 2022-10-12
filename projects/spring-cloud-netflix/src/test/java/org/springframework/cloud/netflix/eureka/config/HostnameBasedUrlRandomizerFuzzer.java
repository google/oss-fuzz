/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.cloud.netflix.eureka.config;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import java.util.ArrayList;
import java.util.List;
import org.springframework.cloud.netflix.eureka.config.HostnameBasedUrlRandomizer;
public class HostnameBasedUrlRandomizerFuzzer {

    FuzzedDataProvider dataProvider;

    public HostnameBasedUrlRandomizerFuzzer(FuzzedDataProvider dataProvider) {
        this.dataProvider = dataProvider;
    }

    public String getString() {
        return dataProvider.consumeString(16);
    }

    public ArrayList<String> getStringArrayList() {
        ArrayList<String> list = new ArrayList<String>();
        int n = dataProvider.consumeInt(0, 10);
        for (int i = 0; i < n; ++i) {
            list.add(getString());
        }
        return list;
    }

    void test() {
        HostnameBasedUrlRandomizer randomizer = new HostnameBasedUrlRandomizer(getString());
        randomizer.randomize(getStringArrayList());
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider dataProvider) {
        HostnameBasedUrlRandomizerFuzzer closure = new HostnameBasedUrlRandomizerFuzzer(dataProvider);
        closure.test();
    }
}