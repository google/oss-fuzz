// Copyright 2026 Google LLC
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
///////////////////////////////////////////////////////////////////////////
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletionException;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import com.linecorp.armeria.common.HttpData;
import com.linecorp.armeria.common.multipart.MimeParsingException;
import com.linecorp.armeria.common.multipart.Multipart;
import com.linecorp.armeria.common.stream.StreamMessage;

import io.netty.util.concurrent.ImmediateEventExecutor;

public class MultipartFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final String boundary = data.consumeString(70);
        if (boundary.isEmpty()) {
            return;
        }

        // Split the body into chunks to exercise the parser's buffering across boundaries.
        final List<HttpData> chunks = new ArrayList<>();
        final int numChunks = data.consumeInt(1, 8);
        for (int i = 0; i < numChunks - 1; i++) {
            chunks.add(HttpData.wrap(data.consumeBytes(data.consumeInt(0, 256))));
        }
        chunks.add(HttpData.wrap(data.consumeRemainingAsBytes()));

        try {
            Multipart.from(boundary, StreamMessage.of(chunks.toArray(new HttpData[0])))
                     // Avoid initializing the default event loops, which is slow and irrelevant to parsing.
                     .aggregate(ImmediateEventExecutor.INSTANCE)
                     .join();
        } catch (IllegalArgumentException e) {
            // Invalid boundary
        } catch (CompletionException e) {
            if (!(e.getCause() instanceof MimeParsingException)) {
                throw e;
            }
        }
    }
}
