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

import java.security.Security;
import java.security.cert.CertificateException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/**
 * CMP messages (RFC 9810) from arbitrary bytes. A protected message is verified the way a CA or end
 * entity would: by its password-based MAC under a fixed password, whose salt, OWF and iteration count
 * come from the message, or by its signature against each certificate it carries.
 */
public class CMPFuzzer
{
    // IllegalArgumentException and IllegalStateException (ASN1ParsingException among them) are how
    // the library reports a malformed structure it meets while parsing on demand, so they end a run
    // quietly; any other unchecked exception, such as a NullPointerException, is a finding.

    private static final char[] PASSWORD = "password".toCharArray();
    // the iteration count a message may ask the password-based MAC for
    private static final int MAX_ITERATIONS = 10000;

    public static void fuzzerInitialize()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void fuzzerTestOneInput(byte[] data)
    {
        try
        {
            GeneralPKIMessage message = new GeneralPKIMessage(data);
            message.getHeader().getSender();
            message.getHeader().getTransactionID();
            message.getBody().getType();
            if (!message.hasProtection())
            {
                return;
            }
            ProtectedPKIMessage protectedMessage = new ProtectedPKIMessage(message);
            if (protectedMessage.hasPasswordBasedMacProtection())
            {
                protectedMessage.verify(new PKMACBuilder(new JcePKMACValuesCalculator().setProvider("BC"), MAX_ITERATIONS),
                    PASSWORD);
            }
            else
            {
                X509CertificateHolder[] certs = protectedMessage.getCertificates();
                for (int i = 0; i != certs.length; i++)
                {
                    try
                    {
                        protectedMessage.verify(new JcaContentVerifierProviderBuilder().setProvider("BC").build(certs[i]));
                    }
                    catch (OperatorCreationException | CertificateException | CMPException e)
                    {
                        // a certificate whose key cannot verify this signature
                    }
                }
            }
        }
        catch (java.io.IOException | CMPException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed input, or a MAC under parameters the builder refuses
        }
    }
}
