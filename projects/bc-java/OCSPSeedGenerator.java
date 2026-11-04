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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Writes the seed corpus for OCSPFuzzer into the directory given: signed responses from RSA and EC
 * responders carrying a good, a revoked and an unknown status and a nonce, a non-successful response,
 * and unsigned and signed requests. Generated at build time, as no OCSP samples are kept as files.
 */
public class OCSPSeedGenerator
{
    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        File dir = new File(args[0]);
        dir.mkdirs();

        DigestCalculator sha1 = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
            .get(CertificateID.HASH_SHA1);
        String[][] responders = { { "RSA", "SHA256withRSA" }, { "EC", "SHA256withECDSA" } };
        for (int r = 0; r != responders.length; r++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(responders[r][0], "BC");
            kpg.initialize(responders[r][0].equals("RSA") ? 2048 : 256);
            KeyPair kp = kpg.generateKeyPair();
            ContentSigner signer = new JcaContentSignerBuilder(responders[r][1]).setProvider("BC").build(kp.getPrivate());
            X500Name name = new X500Name("CN=OCSP Responder " + responders[r][0]);
            Date now = new Date();
            X509CertificateHolder cert = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, now,
                new Date(now.getTime() + 86400000L), name, kp.getPublic()).build(signer);

            Extensions nonce = new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                new DEROctetString(new DEROctetString(new byte[16]))));

            BasicOCSPRespBuilder builder = new JcaBasicOCSPRespBuilder(kp.getPublic(), sha1);
            builder.addResponse(new CertificateID(sha1, cert, BigInteger.valueOf(2)), CertificateStatus.GOOD);
            builder.addResponse(new CertificateID(sha1, cert, BigInteger.valueOf(3)),
                new RevokedStatus(now, CRLReason.keyCompromise));
            builder.addResponse(new CertificateID(sha1, cert, BigInteger.valueOf(4)), new UnknownStatus());
            builder.setResponseExtensions(nonce);
            BasicOCSPResp basic = builder.build(signer, new X509CertificateHolder[]{ cert }, now);
            write(dir, "resp-" + responders[r][0], new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded());

            OCSPReqBuilder request = new OCSPReqBuilder();
            request.addRequest(new CertificateID(sha1, cert, BigInteger.valueOf(2)));
            request.setRequestExtensions(nonce);
            write(dir, "req-" + responders[r][0], request.build().getEncoded());
            request.setRequestorName(name);
            write(dir, "req-signed-" + responders[r][0],
                request.build(signer, new X509CertificateHolder[]{ cert }).getEncoded());
        }
        write(dir, "resp-try-later", new OCSPRespBuilder().build(OCSPRespBuilder.TRY_LATER, null).getEncoded());
    }

    private static void write(File dir, String name, byte[] data)
        throws IOException
    {
        FileOutputStream out = new FileOutputStream(new File(dir, name));
        try
        {
            out.write(data);
        }
        finally
        {
            out.close();
        }
    }
}
