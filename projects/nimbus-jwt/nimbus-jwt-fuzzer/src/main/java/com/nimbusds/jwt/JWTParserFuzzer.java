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

package com.nimbusds.jwt;

import java.text.ParseException;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;


public class JWTParserFuzzer {

    private FuzzedDataProvider fuzzedDataProvider;

    public JWTParserFuzzer(FuzzedDataProvider fuzzedDataProvider) throws Exception {
        this.fuzzedDataProvider = fuzzedDataProvider;
    }

    void test() {
        try {
            JWT jwt = JWTParser.parse(fuzzedDataProvider.consumeRemainingAsString());
        } catch (ParseException exception) {
            /* ignore */
        } catch (IllegalArgumentException exception) {
            /* ignore */
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider fuzzedDataProvider)  throws Exception {

        JWTParserFuzzer fixture = new JWTParserFuzzer(fuzzedDataProvider);
        fixture.test();
    }
}