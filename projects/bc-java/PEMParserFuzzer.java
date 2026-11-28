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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.Security;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.encoders.DecoderException;

/**
 * OpenSSL-style PEM through PEMParser, with each object it returns carried on into the code an
 * application hands it to: key pairs, public and private keys through JcaPEMKeyConverter, certificates
 * and CRLs through the JCA converters, certification requests, and the two encrypted private key forms
 * decrypted under a fixed password, which runs their PBE and KDF parameter handling.
 */
public class PEMParserFuzzer
{
    // IllegalArgumentException and IllegalStateException (ASN1ParsingException among them) are how
    // the library reports a malformed structure it meets while parsing on demand, so they end a run
    // quietly; any other unchecked exception, such as a NullPointerException, is a finding.

    private static final char[] PASSWORD = "password".toCharArray();

    private static JcaPEMKeyConverter keys;

    public static void fuzzerInitialize()
    {
        Security.addProvider(new BouncyCastleProvider());
        keys = new JcaPEMKeyConverter().setProvider("BC");
    }

    public static void fuzzerTestOneInput(byte[] data)
    {
        PEMParser parser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(data)));
        try
        {
            Object obj;
            while ((obj = parser.readObject()) != null)
            {
                convert(obj);
            }
        }
        catch (IOException | DecoderException e)
        {
            // malformed input
        }
    }

    private static void convert(Object obj)
    {
        try
        {
            if (obj instanceof PEMKeyPair)
            {
                keys.getKeyPair((PEMKeyPair)obj);
            }
            else if (obj instanceof SubjectPublicKeyInfo)
            {
                keys.getPublicKey((SubjectPublicKeyInfo)obj);
            }
            else if (obj instanceof PrivateKeyInfo)
            {
                keys.getPrivateKey((PrivateKeyInfo)obj);
            }
            else if (obj instanceof PEMEncryptedKeyPair)
            {
                keys.getKeyPair(((PEMEncryptedKeyPair)obj).decryptKeyPair(
                    new JcePEMDecryptorProviderBuilder().setProvider("BC").build(PASSWORD)));
            }
            else if (obj instanceof PKCS8EncryptedPrivateKeyInfo)
            {
                keys.getPrivateKey(((PKCS8EncryptedPrivateKeyInfo)obj).decryptPrivateKeyInfo(
                    new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC").build(PASSWORD)));
            }
            else if (obj instanceof X509CertificateHolder)
            {
                X509CertificateHolder holder = (X509CertificateHolder)obj;
                holder.getExtensions();
                holder.getSubject().toString();
                new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder).toString();
            }
            else if (obj instanceof X509CRLHolder)
            {
                X509CRLHolder holder = (X509CRLHolder)obj;
                holder.getRevokedCertificates();
                new JcaX509CRLConverter().setProvider("BC").getCRL(holder).toString();
            }
            else if (obj instanceof PKCS10CertificationRequest)
            {
                PKCS10CertificationRequest request = (PKCS10CertificationRequest)obj;
                request.getAttributes();
                request.getSubject().toString();
                new JcaPKCS10CertificationRequest(request).setProvider("BC").getPublicKey();
            }
        }
        catch (IOException | GeneralSecurityException | OperatorCreationException | PKCSException
            | IllegalArgumentException | IllegalStateException e)
        {
            // a key, certificate or request that does not convert, or the wrong password
        }
    }
}
