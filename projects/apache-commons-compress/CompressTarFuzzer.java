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

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarFile;

import java.io.InputStream;
import java.io.IOException;

// Keeping class name the same so corpus doesn't change
// See: https://google.github.io/oss-fuzz/faq/#what-happens-when-i-rename-a-fuzz-target-
public class CompressTarFuzzer extends BaseTests {
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            TarFile tf = new TarFile(data);
            for (TarArchiveEntry entry : tf.getEntries()) {
                InputStream is = tf.getInputStream(entry);
                is.read(new byte[1024]);
            }
            tf.close();
        } catch (IOException ignored) {
        }
    }
}
