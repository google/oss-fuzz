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

import org.apache.hadoop.fs.*;

import java.io.*;
import java.util.concurrent.ExecutionException;


class FileUtilFuzzer {
    static String currentDir = new File("").getAbsolutePath();

    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        try {
            boolean b = data.consumeBoolean();
            byte[] b1 = data.consumeBytes(5000);
            byte[] b2 = data.consumeRemainingAsBytes();

            FileUtil.unZip(new ByteArrayInputStream(b1), new File(currentDir));
            FileUtil.unTar(new ByteArrayInputStream(b2), new File(currentDir), b);
        } catch (IOException | ExecutionException | InterruptedException e) {
        }
    }
}