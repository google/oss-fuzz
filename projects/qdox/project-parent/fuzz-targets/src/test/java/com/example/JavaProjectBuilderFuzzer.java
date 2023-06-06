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

import com.thoughtworks.qdox.JavaProjectBuilder;
import com.thoughtworks.qdox.model.JavaSource;
import com.thoughtworks.qdox.parser.ParseException;

import java.io.StringReader;
import java.util.EmptyStackException;

class JavaProjectBuilderFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try {
            JavaProjectBuilder builder = new JavaProjectBuilder();
            JavaSource src = builder.addSource(new StringReader(data.consumeRemainingAsString()));

            src.getPackage();
            src.getImports();
            src.getClasses();
        } catch (ParseException | ArrayIndexOutOfBoundsException | NullPointerException | EmptyStackException e) {
            // Need to catch in order to find more interesting bugs.
        }
    }
}