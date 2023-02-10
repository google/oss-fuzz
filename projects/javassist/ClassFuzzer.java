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
import java.lang.RuntimeException;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CannotCompileException;
import javassist.NotFoundException;
import java.lang.NullPointerException;


public class ClassFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ClassPool pool = ClassPool.getDefault();
        CtClass cc = null;
        
        try {
            cc = pool.makeClass(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
        } catch (IOException | RuntimeException e) {
        }

        try {
            cc.getSuperclass();
            cc.getNestedClasses();
            cc.getClassFile();
            cc.getInterfaces();
            cc.getDeclaringClass();
            cc.getComponentType();
        } catch (NotFoundException | NullPointerException e) {
        }

        try {
            cc.toBytecode();
        } catch (IOException | NullPointerException | CannotCompileException e) {
        }
    }
}
