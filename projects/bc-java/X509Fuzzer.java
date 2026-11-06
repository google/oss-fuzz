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
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.cert.X509CertificateReviewer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Certificates and CRLs through the BC CertificateFactory, which reads DER, a PEM block or a PKCS#7
 * bundle, with every accessor called on what it returns: the extensions are parsed lazily, so most of
 * the extension code runs only when a getter asks. Each certificate is also checked against itself as
 * if self-signed, and the bytes go through the structural reviewer, which reports problems rather than
 * throwing.
 */
public class X509Fuzzer
{
    // IllegalArgumentException and IllegalStateException (ASN1ParsingException among them) are how
    // the library reports a malformed structure it meets while parsing on demand, so they end a run
    // quietly; any other unchecked exception, such as a NullPointerException, is a finding.

    private static CertificateFactory factory;

    public static void fuzzerInitialize()
    {
        Security.addProvider(new BouncyCastleProvider());
        try
        {
            factory = CertificateFactory.getInstance("X.509", "BC");
        }
        catch (GeneralSecurityException e)
        {
            throw new IllegalStateException(e);
        }
    }

    public static void fuzzerTestOneInput(byte[] data)
    {
        try
        {
            Collection certs = factory.generateCertificates(new ByteArrayInputStream(data));
            for (Iterator it = certs.iterator(); it.hasNext();)
            {
                X509Certificate cert = (X509Certificate)it.next();
                try
                {
                    exercise(cert);
                }
                catch (IllegalArgumentException | IllegalStateException e)
                {
                    // a malformed part parsed on demand
                }
            }
        }
        catch (CertificateException e)
        {
            // malformed input
        }

        try
        {
            Collection crls = factory.generateCRLs(new ByteArrayInputStream(data));
            for (Iterator it = crls.iterator(); it.hasNext();)
            {
                X509CRL crl = (X509CRL)it.next();
                try
                {
                    exercise(crl);
                }
                catch (IllegalArgumentException | IllegalStateException e)
                {
                    // a malformed part parsed on demand
                }
            }
        }
        catch (CRLException e)
        {
            // malformed input
        }

        // the reviewer reports problems as findings and is not to throw for any input
        X509CertificateReviewer.reviewStructure(data);
    }

    private static void exercise(X509Certificate cert)
    {
        cert.toString();
        cert.hashCode();
        cert.getSubjectX500Principal().getName();
        cert.getIssuerX500Principal().getName();
        cert.getSerialNumber();
        cert.getNotBefore();
        cert.getNotAfter();
        cert.getSigAlgName();
        cert.getSigAlgParams();
        cert.getKeyUsage();
        cert.getBasicConstraints();
        cert.getIssuerUniqueID();
        cert.getSubjectUniqueID();
        extensionValues(cert.getCriticalExtensionOIDs(), cert);
        extensionValues(cert.getNonCriticalExtensionOIDs(), cert);
        try
        {
            cert.getExtendedKeyUsage();
            cert.getSubjectAlternativeNames();
            cert.getIssuerAlternativeNames();
        }
        catch (CertificateParsingException e)
        {
            // a malformed extension
        }
        PublicKey key = cert.getPublicKey();
        if (key != null)
        {
            key.getEncoded();
            try
            {
                cert.verify(key, "BC");
            }
            catch (GeneralSecurityException e)
            {
                // not self-signed, or an algorithm the key cannot verify
            }
        }
        try
        {
            cert.getEncoded();
        }
        catch (CertificateException e)
        {
            // an encoding the library will not write
        }
    }

    private static void exercise(X509CRL crl)
    {
        crl.toString();
        crl.hashCode();
        crl.getIssuerX500Principal().getName();
        crl.getThisUpdate();
        crl.getNextUpdate();
        crl.getSigAlgName();
        extensionValues(crl.getCriticalExtensionOIDs(), crl);
        extensionValues(crl.getNonCriticalExtensionOIDs(), crl);
        Set revoked = crl.getRevokedCertificates();
        if (revoked != null)
        {
            for (Iterator it = revoked.iterator(); it.hasNext();)
            {
                X509CRLEntry entry = (X509CRLEntry)it.next();
                entry.toString();
                entry.getSerialNumber();
                entry.getRevocationDate();
                entry.getCertificateIssuer();
                entry.getRevocationReason();
                extensionValues(entry.getCriticalExtensionOIDs(), entry);
                extensionValues(entry.getNonCriticalExtensionOIDs(), entry);
            }
        }
        try
        {
            crl.getEncoded();
        }
        catch (CRLException e)
        {
            // an encoding the library will not write
        }
    }

    private static void extensionValues(Set oids, java.security.cert.X509Extension source)
    {
        if (oids == null)
        {
            return;
        }
        for (Iterator it = oids.iterator(); it.hasNext();)
        {
            source.getExtensionValue((String)it.next());
        }
    }
}
