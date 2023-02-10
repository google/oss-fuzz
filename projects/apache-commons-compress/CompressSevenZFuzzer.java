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

import org.apache.commons.compress.archivers.sevenz.SevenZFile;
import org.apache.commons.compress.archivers.sevenz.SevenZFileOptions;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;

import java.io.IOException;
import java.util.logging.LogManager;

public class CompressSevenZFuzzer {
    private static final SevenZFileOptions options = new SevenZFileOptions.Builder()
        .withMaxMemoryLimitInKb(1_000_000)
        .build();

    public static void fuzzerInitialize() {
        LogManager.getLogManager().reset();
    }

    public static void fuzzerTestOneInput(byte[] data) {
        try {
            new SevenZFile(new SeekableInMemoryByteChannel(data), options).close();
        } catch (IOException ignored) {
        }
    }
}
