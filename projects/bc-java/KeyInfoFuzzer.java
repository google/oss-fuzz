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

import java.io.IOException;

/**
 * A PKCS#8 PrivateKeyInfo or X.509 SubjectPublicKeyInfo, through the lightweight key factories for
 * the classical and standardised algorithms (org.bouncycastle.crypto.util) and for the other
 * post-quantum ones (org.bouncycastle.pqc.crypto.util). These choose between the raw and the
 * DER-wrapped forms several algorithms have had, and between the RFC 9881 / RFC 9935 private key
 * CHOICE arms, from bytes an importer does not control.
 */
public class KeyInfoFuzzer
{
    // IllegalArgumentException and IllegalStateException (ASN1ParsingException among them) are how
    // the library reports a malformed structure it meets while parsing on demand, so they end a run
    // quietly; any other unchecked exception, such as a NullPointerException, is a finding.

    public static void fuzzerTestOneInput(byte[] data)
    {
        try
        {
            org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(data);
        }
        catch (IOException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed or unsupported key
        }
        catch (RuntimeException e)
        {
            // this factory reports an algorithm it does not know with a plain RuntimeException; any
            // subclass of it, such as a NullPointerException, is still a finding
            if (e.getClass() != RuntimeException.class)
            {
                throw e;
            }
        }
        try
        {
            org.bouncycastle.crypto.util.PublicKeyFactory.createKey(data);
        }
        catch (IOException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed or unsupported key
        }
        try
        {
            org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(data);
        }
        catch (IOException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed or unsupported key
        }
        try
        {
            org.bouncycastle.pqc.crypto.util.PublicKeyFactory.createKey(data);
        }
        catch (IOException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed or unsupported key
        }
    }
}
