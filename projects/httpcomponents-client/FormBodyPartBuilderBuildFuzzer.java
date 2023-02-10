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
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;

import org.apache.hc.client5.http.entity.mime.ByteArrayBody;
import org.apache.hc.client5.http.entity.mime.ContentBody;
import org.apache.hc.client5.http.entity.mime.FileBody;
import org.apache.hc.client5.http.entity.mime.FormBodyPartBuilder;
import org.apache.hc.client5.http.entity.mime.InputStreamBody;
import org.apache.hc.client5.http.entity.mime.StringBody;
import org.apache.hc.core5.http.ContentType;

public class FormBodyPartBuilderBuildFuzzer {
    private static final int builderNameLength = 255;
    private static final int fieldNameLength = 255;
    private static final int fieldValueLength = 500;
    private static final int bodyContentSize = 2 * fieldValueLength;

    private enum BodyType { ByteArray, File, InputStream, String }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final String builderName = data.consumeString(builderNameLength);
        final ContentBody contentBody;
        try {
            contentBody = generateContentBody(data);
        } catch (IOException ioe) {
            // preparations failed ; exit early
            return;
        };

        try {
            final FormBodyPartBuilder builder = FormBodyPartBuilder.create(builderName, contentBody);

            while (data.remainingBytes() > 0) {
                builder.addField(data.consumeString(fieldNameLength), data.consumeString(fieldValueLength));
            }

            builder.build();
        } catch (IllegalStateException ignored) {
            // ignore expected exceptions
        }
    }

    private static ContentBody generateContentBody(FuzzedDataProvider data) throws IOException {
        final BodyType choice = data.pickValue(BodyType.values());
        final ContentBody contentBody;
        switch (choice) {
            case ByteArray:
                contentBody =
                    new ByteArrayBody(data.consumeBytes(bodyContentSize), data.consumeString(fieldNameLength));
                break;

            case File:
                final File tempFile = File.createTempFile("FileBody", ".bin");

                try {
                    final FileWriter fileWriter = new FileWriter(tempFile);
                    fileWriter.write(data.consumeString(bodyContentSize));
                    fileWriter.close();
                } catch (IOException ioe) {
                    tempFile.delete();
                    throw ioe;
                }

                contentBody = new FileBody(tempFile);
                tempFile.delete();
                break;

            case InputStream:
                final InputStream inputStream = new ByteArrayInputStream(data.consumeBytes(bodyContentSize));
                contentBody = new InputStreamBody(inputStream, data.consumeString(fieldNameLength));
                break;

            case String:
                contentBody = new StringBody(data.consumeString(bodyContentSize), ContentType.DEFAULT_BINARY);
                break;

            default: // should never be reached
                contentBody = null;
                break;
        }

        return contentBody;
    }
}
