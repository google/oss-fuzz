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

import java.io.*;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.lang.IllegalArgumentException;
import java.lang.StringIndexOutOfBoundsException;

import org.zeroturnaround.zip.ZipUtil;
import org.zeroturnaround.zip.ZipException;
import org.zeroturnaround.zip.commons.IOUtils;


class UnpackFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        String str = data.consumeString(100);
        String dir = "/tmp";
        int level = data.consumeInt();
        InputStream is = new ByteArrayInputStream(data.consumeRemainingAsBytes());

        try {
            ZipUtil.unpackEntry(is, str);
            ZipUtil.unpack(is, new File(dir));
            ZipUtil.unwrap(is, new File(dir));
            ZipUtil.repack(is, new File(dir), level);
            IOUtils.closeQuietly(is);
        } catch (ZipException | IllegalArgumentException | StringIndexOutOfBoundsException e) {
        } 
    }
}