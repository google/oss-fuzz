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

import org.mvel2.MVEL;
import org.mvel2.CompileException;
import org.mvel2.ScriptRuntimeException;
import org.mvel2.UnresolveablePropertyException;

class MvelFuzzer {

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        String input = data.consumeRemainingAsString();
        try {
            MVEL.eval(input);
            MVEL.compileExpression(input);
        } catch (UnresolveablePropertyException | CompileException | ArithmeticException | ScriptRuntimeException e) {
            // Documented Exceptions
        } catch (java.lang.AssertionError | RuntimeException e) {
            // Not expected to be thrown but we catch to reach deeper program states.
        }
    }
}