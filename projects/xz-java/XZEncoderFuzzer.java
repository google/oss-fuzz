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
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.UnsupportedOptionsException;
import org.tukaani.xz.XZOutputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class XZEncoderFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ByteArrayInputStream in = new ByteArrayInputStream(data.consumeBytes(300));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        LZMA2Options options = new LZMA2Options();
        try {
            options.setPreset(data.consumeInt(LZMA2Options.PRESET_MIN, LZMA2Options.PRESET_MAX));
        } catch (UnsupportedOptionsException e) {
            throw new RuntimeException(e);
        }

        byte[] buf = data.consumeBytes(300);
        try {
            XZOutputStream xzOut = new XZOutputStream(out, options);
            xzOut.write(buf, 0, buf.length);
            xzOut.finish();
        } catch (IOException e) {}
    }
}