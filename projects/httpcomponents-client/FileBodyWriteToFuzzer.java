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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.apache.hc.client5.http.entity.mime.FileBody;
import org.apache.hc.core5.http.ContentType;

public class FileBodyWriteToFuzzer {
    private static final int FILENAME_MAX_LENGTH = 255;

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // Create objects from fuzzer input
        final ContentType contentType = data.pickValue(contentTypes);
        final String filename = data.consumeString(FILENAME_MAX_LENGTH);
        final String fileContent = data.consumeRemainingAsString();

        // Create needed objects
        final File tempFile;
        try {
            tempFile = File.createTempFile("FileBody", ".bin");
        } catch (IOException ioe) {
            return;
        }

        try {
            final FileWriter fileWriter = new FileWriter(tempFile);
            fileWriter.write(fileContent);
            fileWriter.close();
        } catch (IOException ioe) {
            tempFile.delete();
            return;
        }

        // Actual fuzzing begins here
        try {
            final FileBody fileBody = new FileBody(tempFile, contentType, filename);
            fileBody.writeTo(new ByteArrayOutputStream());
        } catch (IOException ignored) {
            // ignore expected exceptions
        } finally {
            tempFile.delete();
        }
    }

    private static final ContentType[] contentTypes = {ContentType.APPLICATION_ATOM_XML,
        ContentType.APPLICATION_FORM_URLENCODED, ContentType.APPLICATION_JSON, ContentType.APPLICATION_NDJSON,
        ContentType.APPLICATION_OCTET_STREAM, ContentType.APPLICATION_PDF, ContentType.APPLICATION_PROBLEM_JSON,
        ContentType.APPLICATION_PROBLEM_XML, ContentType.APPLICATION_RSS_XML, ContentType.APPLICATION_SOAP_XML,
        ContentType.APPLICATION_SVG_XML, ContentType.APPLICATION_XHTML_XML, ContentType.APPLICATION_XML,
        ContentType.DEFAULT_BINARY, ContentType.DEFAULT_TEXT, ContentType.IMAGE_BMP, ContentType.IMAGE_GIF,
        ContentType.IMAGE_JPEG, ContentType.IMAGE_PNG, ContentType.IMAGE_SVG, ContentType.IMAGE_TIFF,
        ContentType.IMAGE_WEBP, ContentType.MULTIPART_FORM_DATA, ContentType.MULTIPART_MIXED,
        ContentType.MULTIPART_RELATED, ContentType.TEXT_EVENT_STREAM, ContentType.TEXT_HTML, ContentType.TEXT_MARKDOWN,
        ContentType.TEXT_PLAIN, ContentType.TEXT_XML, ContentType.WILDCARD};
}
