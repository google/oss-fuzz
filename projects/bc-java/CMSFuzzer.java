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
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSCompressedData;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataParser;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * CMS messages from arbitrary bytes: SignedData (with every signer verified against every certificate
 * the message carries, counter-signatures included), EnvelopedData and AuthEnvelopedData recipient
 * information, CompressedData with its expansion capped, and the streaming SignedData and EnvelopedData
 * parsers. This replaces CMSEnvelopedDataParserFuzzer, which encrypted the input as content and so
 * only ever parsed messages the library had just generated.
 */
public class CMSFuzzer
{
    // IllegalArgumentException and IllegalStateException (ASN1ParsingException among them) are how
    // the library reports a malformed structure it meets while parsing on demand, so they end a run
    // quietly; any other unchecked exception, such as a NullPointerException, is a finding.

    // a CompressedData message may expand to no more than this
    private static final long EXPANSION_LIMIT = 1 << 20;

    private static DigestCalculatorProvider digests;

    public static void fuzzerInitialize()
    {
        Security.addProvider(new BouncyCastleProvider());
        try
        {
            digests = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException(e);
        }
    }

    public static void fuzzerTestOneInput(byte[] data)
    {
        for (int section = 0; section != 6; section++)
        {
            try
            {
                switch (section)
                {
                case 0: signedData(data); break;
                case 1: envelopedData(data); break;
                case 2: authEnvelopedData(data); break;
                case 3: compressedData(data); break;
                case 4: streamingSignedData(data); break;
                default: streamingEnvelopedData(data); break;
                }
            }
            catch (IllegalArgumentException | IllegalStateException e)
            {
                // a malformed part parsed on demand
            }
        }
    }

    private static void signedData(byte[] data)
    {
        CMSSignedData signed;
        try
        {
            signed = new CMSSignedData(data);
        }
        catch (CMSException e)
        {
            return;
        }
        signed.getSignedContentTypeOID();
        signed.getDigestAlgorithmIDs();
        signed.getCRLs().getMatches(null);
        signed.getAttributeCertificates().getMatches(null);
        Collection certs = signed.getCertificates().getMatches(null);
        verifyAll(signed.getSignerInfos().getSigners(), certs);
    }

    private static void verifyAll(Collection signers, Collection certs)
    {
        for (Iterator it = signers.iterator(); it.hasNext();)
        {
            SignerInformation signer = (SignerInformation)it.next();
            signer.getSID();
            signer.getDigestAlgOID();
            signer.getEncryptionAlgOID();
            signer.getSignedAttributes();
            signer.getUnsignedAttributes();
            for (Iterator c = certs.iterator(); c.hasNext();)
            {
                try
                {
                    signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                        .build((X509CertificateHolder)c.next()));
                }
                catch (CMSException | OperatorCreationException | CertificateException e)
                {
                    // the wrong certificate, a bad signature, or an algorithm the key cannot verify
                }
            }
            verifyAll(signer.getCounterSignatures().getSigners(), certs);
        }
    }

    private static void envelopedData(byte[] data)
    {
        try
        {
            CMSEnvelopedData enveloped = new CMSEnvelopedData(data);
            enveloped.getOriginatorInfo();
            enveloped.getContentEncryptionAlgorithm();
            enveloped.getUnprotectedAttributes();
            recipients(enveloped.getRecipientInfos().getRecipients());
        }
        catch (CMSException e)
        {
            // malformed input
        }
    }

    private static void authEnvelopedData(byte[] data)
    {
        try
        {
            CMSAuthEnvelopedData enveloped = new CMSAuthEnvelopedData(data);
            enveloped.getOriginatorInfo();
            enveloped.getAuthAttrs();
            enveloped.getUnauthAttrs();
            enveloped.getMac();
            recipients(enveloped.getRecipientInfos().getRecipients());
        }
        catch (CMSException e)
        {
            // malformed input
        }
    }

    private static void recipients(Collection recipients)
    {
        for (Iterator it = recipients.iterator(); it.hasNext();)
        {
            RecipientInformation recipient = (RecipientInformation)it.next();
            recipient.getRID();
            recipient.getKeyEncryptionAlgOID();
            recipient.getKeyEncryptionAlgParams();
        }
    }

    private static void compressedData(byte[] data)
    {
        try
        {
            new CMSCompressedData(data).getContent(new ZlibExpanderProvider(EXPANSION_LIMIT));
        }
        catch (CMSException e)
        {
            // malformed input, or content that expands beyond the limit
        }
    }

    private static void streamingSignedData(byte[] data)
    {
        try
        {
            CMSSignedDataParser parser = new CMSSignedDataParser(digests, data);
            CMSTypedStream content = parser.getSignedContent();
            if (content != null)
            {
                drain(content.getContentStream());
            }
            Collection certs = parser.getCertificates().getMatches(null);
            parser.getCRLs().getMatches(null);
            verifyAll(parser.getSignerInfos().getSigners(), certs);
        }
        catch (CMSException | IOException e)
        {
            // malformed input
        }
    }

    private static void streamingEnvelopedData(byte[] data)
    {
        try
        {
            CMSEnvelopedDataParser parser = new CMSEnvelopedDataParser(data);
            parser.getEncryptionAlgOID();
            parser.getUnprotectedAttributes();
            recipients(parser.getRecipientInfos().getRecipients());
        }
        catch (CMSException | IOException e)
        {
            // malformed input
        }
    }

    private static void drain(InputStream in)
        throws IOException
    {
        byte[] buf = new byte[4096];
        while (in.read(buf) >= 0)
        {
            // discard
        }
    }
}
