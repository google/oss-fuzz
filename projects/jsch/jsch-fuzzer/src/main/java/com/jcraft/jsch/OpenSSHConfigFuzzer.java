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

package com.jcraft.jsch;

import java.io.IOException;
import java.nio.ByteBuffer;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.jcraft.jsch.OpenSSHConfig;


public class OpenSSHConfigFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

    public OpenSSHConfigFuzzer(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        this.fuzzedDataProvider = fuzzedDataProvider;
    }

    void test() {
        try {
            OpenSSHConfig config = OpenSSHConfig.parse(fuzzedDataProvider.consumeRemainingAsString());
        } catch (IOException exception) {
            /* ignore */
        } catch (IllegalArgumentException excepion) {
            /* ignore */
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider)  throws Exception {

        OpenSSHConfigFuzzer fixture = new OpenSSHConfigFuzzer(fuzzedDataProvider);
        fixture.test();
    }
}