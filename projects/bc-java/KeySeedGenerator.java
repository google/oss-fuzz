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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * Writes the seed corpus for KeyInfoFuzzer into the directory given: a PKCS#8 PrivateKeyInfo and an
 * X.509 SubjectPublicKeyInfo for each of a spread of algorithms, plus the ML-DSA and ML-KEM private
 * keys in each of the three private key forms. Run at build time, so the seeds follow the encodings
 * the library writes. An algorithm the build does not offer is skipped.
 */
public class KeySeedGenerator
{
    private static final String[][] JCA = {
        { "RSA", "BC", null }, { "EC", "BC", "secp256r1" }, { "EC", "BC", "brainpoolP384r1" },
        { "DSA", "BC", null }, { "Ed25519", "BC", null }, { "Ed448", "BC", null },
        { "X25519", "BC", null }, { "X448", "BC", null },
        { "ML-DSA-44", "BC", null }, { "ML-KEM-768", "BC", null },
        { "SLH-DSA-SHA2-128F", "BC", null }, { "SLH-DSA-SHAKE-128F", "BC", null },
        { "Falcon-512", "BCPQC", null }, { "NTRU", "BCPQC", null }, { "HQC", "BCPQC", null },
        { "NTRULPRime", "BCPQC", null }, { "SNTRUPrime", "BCPQC", null }, { "NTRUPlus", "BCPQC", null },
        { "MAYO", "BCPQC", null }, { "BIKE", "BCPQC", null }
    };

    public static void main(String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        File dir = new File(args[0]);
        dir.mkdirs();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i != JCA.length; i++)
        {
            String name = JCA[i][0];
            try
            {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, JCA[i][1]);
                if (JCA[i][2] != null)
                {
                    kpg.initialize(new ECGenParameterSpec(JCA[i][2]), random);
                }
                else if (name.equals("RSA") || name.equals("DSA"))
                {
                    kpg.initialize(1024, random);
                }
                KeyPair kp = kpg.generateKeyPair();
                String base = name + (JCA[i][2] != null ? "-" + JCA[i][2] : "");
                write(dir, base + ".pkcs8", kp.getPrivate().getEncoded());
                write(dir, base + ".spki", kp.getPublic().getEncoded());
            }
            catch (Exception e)
            {
                System.err.println("seed for " + name + " skipped: " + e);
            }
        }

        // the three RFC 9881 / RFC 9935 private key forms, each a different CHOICE arm
        int[] formats = { MLDSAPrivateKeyParameters.SEED_ONLY, MLDSAPrivateKeyParameters.EXPANDED_KEY,
            MLDSAPrivateKeyParameters.BOTH };
        String[] formatNames = { "seed", "expanded", "both" };

        MLDSAKeyPairGenerator dsa = new MLDSAKeyPairGenerator();
        dsa.init(new MLDSAKeyGenerationParameters(random, MLDSAParameters.ml_dsa_65));
        MLDSAPrivateKeyParameters dsaKey = (MLDSAPrivateKeyParameters)dsa.generateKeyPair().getPrivate();
        MLKEMKeyPairGenerator kem = new MLKEMKeyPairGenerator();
        kem.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_512));
        AsymmetricCipherKeyPair kemPair = kem.generateKeyPair();
        MLKEMPrivateKeyParameters kemKey = (MLKEMPrivateKeyParameters)kemPair.getPrivate();
        for (int i = 0; i != formats.length; i++)
        {
            write(dir, "ML-DSA-65-" + formatNames[i] + ".pkcs8",
                PrivateKeyInfoFactory.createPrivateKeyInfo(dsaKey.withPreferredFormat(formats[i])).getEncoded());
            write(dir, "ML-KEM-512-" + formatNames[i] + ".pkcs8",
                PrivateKeyInfoFactory.createPrivateKeyInfo(kemKey.withPreferredFormat(formats[i])).getEncoded());
        }
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
