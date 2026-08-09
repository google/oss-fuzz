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

import java.util.ArrayList;
import java.util.Collections;
import com.google.javascript.jscomp.parsing.Config;
import com.google.javascript.jscomp.parsing.Config.JsDocParsing;
import com.google.javascript.jscomp.parsing.Config.LanguageMode;
import com.google.javascript.jscomp.parsing.ParserRunner;
import com.google.javascript.jscomp.parsing.ParserRunner.ParseResult;
import com.google.javascript.rhino.*;
import com.google.javascript.rhino.StaticSourceFile.SourceKind;


class ParserFuzzer {
    static SourceKind [] sourceKinds = {SourceKind.STRONG, SourceKind.WEAK, SourceKind.EXTERN, SourceKind.NON_CODE};
    static LanguageMode [] languageModes = {LanguageMode.ECMASCRIPT3, LanguageMode.ECMASCRIPT5,
            LanguageMode.ECMASCRIPT_2015, LanguageMode.ECMASCRIPT_2016, LanguageMode.ECMASCRIPT_2017, LanguageMode.ECMASCRIPT_2018,
            LanguageMode.ECMASCRIPT_2019, LanguageMode.ECMASCRIPT_2020, LanguageMode.ECMASCRIPT_2021, LanguageMode.ES_NEXT,
            LanguageMode.UNSTABLE, LanguageMode.UNSUPPORTED};
    static JsDocParsing [] jsDocParsings = {JsDocParsing.INCLUDE_ALL_COMMENTS, JsDocParsing.TYPES_ONLY,
            JsDocParsing.INCLUDE_DESCRIPTIONS_WITH_WHITESPACE, JsDocParsing.INCLUDE_DESCRIPTIONS_NO_WHITESPACE};
    static Config.RunMode [] runModes = {Config.RunMode.KEEP_GOING, Config.RunMode.STOP_AFTER_ERROR};
    static Config.StrictMode [] strictModes = {Config.StrictMode.STRICT, Config.StrictMode.SLOPPY};
    static TestErrorReporter [] testErrorReporters = {new TestErrorReporter().expectAllWarnings(), new TestErrorReporter().expectAllErrors()};

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try {
            String name = data.consumeString(200);
            StaticSourceFile file = new SimpleSourceFile(name, data.pickValue(sourceKinds));
            Config config = ParserRunner.createConfig(data.pickValue(languageModes), data.pickValue(jsDocParsings),
                    data.pickValue(runModes), null, data.consumeBoolean(), data.pickValue(strictModes));
            TestErrorReporter testErrorReporter = data.pickValue(testErrorReporters);
            String sourceString = data.consumeRemainingAsString();
            ParseResult result = ParserRunner.parse(file, sourceString, config, testErrorReporter);
        } catch (RuntimeException e) {
            // Need to catch RuntimeException to pass fuzzing blocker.
        }
    }

     static class TestErrorReporter implements ErrorReporter {
        private final ArrayList<String> expectedErrors = new ArrayList<>();
        private final ArrayList<String> expectedWarnings = new ArrayList<>();
        private final ArrayList<String> seenErrors = new ArrayList<>();
        private final ArrayList<String> seenWarnings = new ArrayList<>();

        @Override
        public void error(String message, String sourceName, int line, int lineOffset) {
            this.seenErrors.add(message);
        }

        @Override
        public void warning(String message, String sourceName, int line, int lineOffset) {
            this.seenWarnings.add(message);
        }

        public TestErrorReporter expectAllErrors(String... errors) {
            Collections.addAll(this.expectedErrors, errors);
            return this;
        }

        public TestErrorReporter expectAllWarnings(String... warnings) {
            Collections.addAll(this.expectedWarnings, warnings);
            return this;
        }
    }
}