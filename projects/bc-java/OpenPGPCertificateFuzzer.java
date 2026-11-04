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

import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKeyReader;

/**
 * Certificates and keys through the high-level openpgp.api layer, which unlike the packet-level
 * PGPFuzzer evaluates them: binding and revocation signatures are verified, subkeys and user IDs are
 * resolved against them, and the policy decides which keys are usable for signing and encryption now.
 */
public class OpenPGPCertificateFuzzer
{
    // IllegalArgumentException and IllegalStateException (ASN1ParsingException among them) are how
    // the library reports a malformed structure it meets while parsing on demand, so they end a run
    // quietly; any other unchecked exception, such as a NullPointerException, is a finding.

    private static OpenPGPKeyReader reader;

    public static void fuzzerInitialize()
    {
        reader = new OpenPGPKeyReader();
    }

    public static void fuzzerTestOneInput(byte[] data)
    {
        List certs;
        try
        {
            certs = reader.parseKeysOrCertificates(data);
        }
        catch (java.io.IOException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed input
            return;
        }
        Date now = new Date();
        for (Iterator it = certs.iterator(); it.hasNext();)
        {
            OpenPGPCertificate cert = (OpenPGPCertificate)it.next();
            try
            {
                cert.getKeyIdentifier();
                cert.getPrimaryKey().getCreationTime();
                cert.getAllUserIds();
                cert.getIdentities();
                cert.getPrimaryUserId();
                cert.getSigningKeys();
                cert.getEncryptionKeys();
                cert.getComponents();
                for (Iterator keys = cert.getKeys().iterator(); keys.hasNext();)
                {
                    OpenPGPCertificate.OpenPGPComponentKey key = (OpenPGPCertificate.OpenPGPComponentKey)keys.next();
                    key.isBoundAt(now);
                    key.isSigningKey();
                    key.isEncryptionKey();
                    key.isCertificationKey();
                }
                cert.toAsciiArmoredString();
            }
            catch (java.io.IOException | IllegalArgumentException | IllegalStateException e)
            {
                // a certificate the layer refuses to evaluate
            }
        }
    }
}
