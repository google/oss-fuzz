// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in co  mpliance with the License.
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
//////////////////////////////////////////////////////////////////////////////////

package com.example;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import org.apache.commons.fileupload2.core.FileItem;
import org.apache.commons.fileupload2.core.AbstractFileUpload;
import org.apache.commons.fileupload2.core.FileUploadException;
import org.apache.commons.fileupload2.core.MultipartInput;
import org.apache.commons.fileupload2.core.DiskFileItemFactory;
import org.apache.commons.fileupload2.javax.JavaxServletFileUpload;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;


public class FileUploadFuzzer {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data)
            throws IOException, FileUploadException {
        DiskFileItemFactory factory = DiskFileItemFactory.builder()
                .setPath(new File("/tmp/abc").toPath())
                .get();
        AbstractFileUpload upload = new JavaxServletFileUpload(factory);

        // is set to tomcats default to approach CVE-2023-24998
        upload.setMaxFileCount(10000);

        String contentType = data.consumeAsciiString(200);
        String multipartData = data.consumeRemainingAsString();
        List<FileItem> fileItems = null;

        try {
            Util.parseUpload(upload, "-----1234\r\n" + multipartData + "-----1234--\r\n");
            Util.parseUpload(upload, multipartData.getBytes(StandardCharsets.US_ASCII), contentType);
        } catch (Exception e) {

        }
    }
}
