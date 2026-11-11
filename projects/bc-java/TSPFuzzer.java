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
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

/**
 * RFC 3161 time-stamp responses and requests from arbitrary bytes. The token in a response is read in
 * full and validated against every certificate it carries, as a relying party validating a stamp would,
 * which runs the ESS signing-certificate checks as well as the CMS signature.
 */
public class TSPFuzzer
{
    // IllegalArgumentException and IllegalStateException (ASN1ParsingException among them) are how
    // the library reports a malformed structure it meets while parsing on demand, so they end a run
    // quietly; any other unchecked exception, such as a NullPointerException, is a finding.

    public static void fuzzerInitialize()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void fuzzerTestOneInput(byte[] data)
    {
        try
        {
            TimeStampResponse response = new TimeStampResponse(data);
            response.getStatus();
            response.getStatusString();
            response.getFailInfo();
            TimeStampToken token = response.getTimeStampToken();
            if (token != null)
            {
                token(token);
            }
        }
        catch (TSPException | IOException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed input
        }
        try
        {
            TimeStampRequest request = new TimeStampRequest(data);
            request.getMessageImprintAlgOID();
            request.getMessageImprintDigest();
            request.getNonce();
            request.getReqPolicy();
            request.getExtensionOIDs();
        }
        catch (IOException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed input
        }
    }

    private static void token(TimeStampToken token)
    {
        TimeStampTokenInfo info = token.getTimeStampInfo();
        info.getGenTime();
        info.getAccuracy();
        info.getNonce();
        info.getTsa();
        info.getPolicy();
        info.getMessageImprintAlgOID();
        token.getSID();
        token.getSignedAttributes();
        token.getUnsignedAttributes();
        Collection certs = token.getCertificates().getMatches(null);
        for (Iterator it = certs.iterator(); it.hasNext();)
        {
            try
            {
                token.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                    .build((X509CertificateHolder)it.next()));
            }
            catch (TSPException | OperatorCreationException | CertificateException e)
            {
                // not the signer's certificate, or a stamp that does not validate
            }
        }
    }
}
