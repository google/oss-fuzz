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

import java.io.IOException;
import java.io.StringReader;

import com.google.gwt.dev.js.ast.JsBlock;
import com.google.gwt.dev.js.ast.JsProgram;
import com.google.gwt.dev.js.JsParser;
import com.google.gwt.dev.js.JsParserException;
import com.google.gwt.dev.js.ast.JsRootScope;
import com.google.gwt.dev.jjs.SourceInfo;
import com.google.gwt.dev.jjs.SourceOrigin;


class JsParserFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        StringReader sr = new StringReader(data.consumeRemainingAsString());
        try {
            JsProgram program = new JsProgram();
            SourceInfo rootSourceInfo = program.createSourceInfo(1, data.consumeString(100));
            JsBlock block = program.getGlobalBlock();
            JsParser.parse(SourceOrigin.UNKNOWN, JsRootScope.INSTANCE, sr);
            JsParser.parseInto(rootSourceInfo, program.getScope(), block, sr);
        } catch (IOException | JsParserException e) {
        } catch (RuntimeException e) {
            // Need to catch this error in order to reach deeper states.
        }
    }
}
