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
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/**
 * OCSP responses and requests from arbitrary bytes: every SingleResp with its status, times and
 * extensions, the responder ID, and the signature checked against every certificate the message
 * carries, as a client checking a response would.
 */
public class OCSPFuzzer
{
    // IllegalArgumentException and IllegalStateException (ASN1ParsingException among them) are how
    // the library reports a malformed structure it meets while parsing on demand, so they end a run
    // quietly; any other unchecked exception, such as a NullPointerException, is a finding.

    private static JcaContentVerifierProviderBuilder verifiers;

    public static void fuzzerInitialize()
    {
        Security.addProvider(new BouncyCastleProvider());
        verifiers = new JcaContentVerifierProviderBuilder().setProvider("BC");
    }

    public static void fuzzerTestOneInput(byte[] data)
    {
        try
        {
            response(new OCSPResp(data));
        }
        catch (java.io.IOException | OCSPException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed input
        }
        try
        {
            request(new OCSPReq(data));
        }
        catch (java.io.IOException | OCSPException | IllegalArgumentException | IllegalStateException e)
        {
            // malformed input
        }
    }

    private static void response(OCSPResp resp)
        throws OCSPException
    {
        resp.getStatus();
        Object obj = resp.getResponseObject();
        if (!(obj instanceof BasicOCSPResp))
        {
            return;
        }
        BasicOCSPResp basic = (BasicOCSPResp)obj;
        basic.getResponderId();
        basic.getProducedAt();
        basic.getSignatureAlgOID();
        basic.getExtensionOIDs();
        SingleResp[] responses = basic.getResponses();
        for (int i = 0; i != responses.length; i++)
        {
            responses[i].getCertID().getSerialNumber();
            responses[i].getCertStatus();
            responses[i].getThisUpdate();
            responses[i].getNextUpdate();
            responses[i].getExtensionOIDs();
        }
        X509CertificateHolder[] certs = basic.getCerts();
        for (int i = 0; i != certs.length; i++)
        {
            try
            {
                basic.isSignatureValid(verifiers.build(certs[i]));
            }
            catch (OperatorCreationException | CertificateException | OCSPException e)
            {
                // a certificate whose key cannot verify this signature
            }
        }
    }

    private static void request(OCSPReq req)
        throws OCSPException
    {
        req.getVersionNumber();
        req.getRequestorName();
        req.getExtensionOIDs();
        Req[] list = req.getRequestList();
        for (int i = 0; i != list.length; i++)
        {
            list[i].getCertID().getHashAlgOID();
            list[i].getSingleRequestExtensions();
        }
        if (req.isSigned())
        {
            X509CertificateHolder[] certs = req.getCerts();
            for (int i = 0; i != certs.length; i++)
            {
                try
                {
                    req.isSignatureValid(verifiers.build(certs[i]));
                }
                catch (OperatorCreationException | CertificateException | OCSPException e)
                {
                    // a certificate whose key cannot verify this signature
                }
            }
        }
    }
}
