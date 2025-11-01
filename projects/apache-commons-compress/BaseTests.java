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

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.compressors.CompressorInputStream;

import java.io.IOException;
import java.util.logging.LogManager;

// Class with common functionality shared among fuzzing harnesses
public class BaseTests {
    public static void fuzzerInitialize() {
        LogManager.getLogManager().reset();
    }

    // Fuzz archiver streams by reading every entry
    public static void fuzzArchiveInputStream(ArchiveInputStream is) throws IOException {
        ArchiveEntry entry;
        while ((entry = is.getNextEntry()) != null) {
            is.read(new byte[1024]);
        }
        is.close();
    }

    // Fuzz compressor streams by reading them
    public static void fuzzCompressorInputStream(CompressorInputStream is) throws IOException {
        is.read(new byte[1024]);
        is.close();
    }
}
