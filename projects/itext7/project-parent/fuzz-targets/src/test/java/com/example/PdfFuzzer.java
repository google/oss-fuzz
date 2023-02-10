// Copyright 2021 Google LLC
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

import java.io.*;
import java.nio.charset.StandardCharsets;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.io.exceptions.*;

public class PdfFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            InputStream stream = new ByteArrayInputStream(data.consumeRemainingAsString().getBytes(StandardCharsets.UTF_8));
            PdfReader reader = new PdfReader(stream);
            PdfDocument pdfDoc = new PdfDocument(reader);
        } 
        
        /*  
            Catching multiple exceptions and errors in order to allow fuzzing to continue to the most intresting findings.
            As of this commit, libfuzzer is triggering com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow in local testing.
            Once that issue is addressed, further testing can be performed by a removing some of these caught exceptions
            and errors.  In particular, the java.lang.AssertionError may be a bug that should be addressed.
        */
        catch (java.io.IOException | com.itextpdf.io.exceptions.IOException | com.itextpdf.kernel.exceptions.PdfException
            | java.lang.AssertionError | java.lang.ClassCastException | java.lang.StringIndexOutOfBoundsException e) { }
    }
}