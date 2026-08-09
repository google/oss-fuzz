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

package org.eclipse.osgi;

import org.osgi.service.condpermadmin.ConditionInfo;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;


public class ConditionInfoFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

    public ConditionInfoFuzzer(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        this.fuzzedDataProvider = fuzzedDataProvider;
    }

    void test() {
        try {
            ConditionInfo info = new ConditionInfo(fuzzedDataProvider.consumeRemainingAsAsciiString());
            info.toString();
        } catch (IllegalArgumentException ex) {
            /* ignore */
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider)  throws Exception {

        ConditionInfoFuzzer fixture = new ConditionInfoFuzzer(fuzzedDataProvider);
        fixture.test();
    }
}