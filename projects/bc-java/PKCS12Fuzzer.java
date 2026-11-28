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
////////////////////////////////////////////////////////////////////////////////

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * PKCS#12 key stores through the BC KeyStore, which decrypts every bag at load time: the MAC, the
 * PBES1, PBES2 and PBMAC1 parameters and their iteration counts, the bag structure, and the keys and
 * certificates the bags hold. Each store is loaded under a fixed password, then every entry is read.
 * Both the legacy-MAC and the RFC 9579 PBMAC1 store types are fuzzed. A null password is not tried: BC
 * refuses to load a MAC-protected store without one with a NullPointerException, by design.
 */
public class PKCS12Fuzzer
{
    // IllegalArgumentException and IllegalStateException (ASN1ParsingException among them) are how
    // the library reports a malformed structure it meets while parsing on demand, so they end a run
    // quietly; any other unchecked exception, such as a NullPointerException, is a finding.

    private static final char[] PASSWORD = "password".toCharArray();
    private static final String[] TYPES = { "PKCS12", "PKCS12-PBMAC1" };

    // held so the level set on it is not lost when the logger is collected
    private static java.util.logging.Logger log;

    public static void fuzzerInitialize()
    {
        // a store asking for more iterations than this is refused on load rather than derived: the
        // fuzzer's time goes on the structure, not on PBKDF2 (BC's own default bound is far higher)
        System.setProperty("org.bouncycastle.pkcs12.max_it_count", "10000");
        Security.addProvider(new BouncyCastleProvider());
        // the key store logs each unrecognised bag at INFO, which would flood the fuzzer's output
        log = java.util.logging.Logger.getLogger("org.bouncycastle");
        log.setLevel(java.util.logging.Level.WARNING);
    }

    public static void fuzzerTestOneInput(byte[] data)
    {
        for (int t = 0; t != TYPES.length; t++)
        {
            load(TYPES[t], data, PASSWORD);
        }
    }

    private static void load(String type, byte[] data, char[] password)
    {
        try
        {
            KeyStore store = KeyStore.getInstance(type, "BC");
            store.load(new ByteArrayInputStream(data), password);
            for (Enumeration aliases = store.aliases(); aliases.hasMoreElements();)
            {
                String alias = (String)aliases.nextElement();
                store.isKeyEntry(alias);
                store.getCreationDate(alias);
                Certificate[] chain = store.getCertificateChain(alias);
                if (chain != null)
                {
                    for (int i = 0; i != chain.length; i++)
                    {
                        chain[i].getEncoded();
                    }
                }
                Certificate cert = store.getCertificate(alias);
                if (cert != null)
                {
                    store.getCertificateAlias(cert);
                }
                try
                {
                    store.getKey(alias, password);
                }
                catch (GeneralSecurityException e)
                {
                    // the wrong password, or a key the provider cannot rebuild
                }
            }
        }
        catch (IOException | GeneralSecurityException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed input, the wrong password or an algorithm not offered
        }
    }
}
