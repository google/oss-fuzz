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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyStore;

import net.jsign.AuthenticodeSigner;
import net.jsign.mscab.MSCabinetFile;

public class AuthenticodeCabSignerFuzzer {

    public static void fuzzerTestOneInput(byte[] data) throws Exception {
        File file = File.createTempFile("jsign-fuzzer", "cab");
        file.deleteOnExit();
        Files.write(file.toPath(), data);

        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(Thread.currentThread().getContextClassLoader().getResourceAsStream("keystore.jks"), "password".toCharArray());

        try {
            AuthenticodeSigner signer = new AuthenticodeSigner(keystore, "test", "password").withTimestamping(false);
            signer.sign(new MSCabinetFile(file));
        } catch (IOException e) {
            // expected
        }
    }
}
