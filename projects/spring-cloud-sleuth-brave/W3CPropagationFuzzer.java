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
package org.springframework.cloud.sleuth.brave.bridge;

import java.lang.reflect.*;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class W3CPropagationFuzzer {
    static Method extractContextFromTraceParent_Method;

    public static void fuzzerInitialize() {
        // expose a private method "extractContextFromTraceParent" of the class W3CPropagation                                                                                                                                              
        try {
            extractContextFromTraceParent_Method = W3CPropagation.class.getDeclaredMethod("extractContextFromTraceParent", String.class);
            extractContextFromTraceParent_Method.setAccessible(true);
        } catch (NoSuchMethodException e) {
        } catch (ExceptionInInitializerError e) {}
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String content = data.consumeRemainingAsString();
        try {
            extractContextFromTraceParent_Method.invoke(W3CPropagation.class, content);
        } catch (IllegalAccessException e) {
        } catch (InvocationTargetException e) {}
    }
}
