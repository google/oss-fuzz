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
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;

/**
 * OpenPGP packets from arbitrary bytes, ASCII-armoured or binary as PGPUtil.getDecoderStream decides,
 * through BcPGPObjectFactory: key rings with their keys, user IDs, user attributes and signatures,
 * signature lists with their subpackets, and compressed and literal data, read with expansion capped
 * and the compressed contents parsed in turn.
 */
public class PGPFuzzer
{
    // compressed or literal content is read no further than this
    private static final int READ_LIMIT = 1 << 20;
    // compressed data nested no deeper than this
    private static final int MAX_DEPTH = 4;

    public static void fuzzerTestOneInput(byte[] data)
    {
        try
        {
            objects(PGPUtil.getDecoderStream(new ByteArrayInputStream(data)), 0);
        }
        catch (IOException | PGPException e)
        {
            // malformed input
        }
        catch (IllegalArgumentException | IllegalStateException e)
        {
            // how a packet sequence the specification forbids is reported - a v4 SKESK before a v2 SEIPD,
            // say - as elsewhere in the library; any other unchecked exception is a finding
        }
    }

    private static void objects(InputStream in, int depth)
        throws IOException, PGPException
    {
        BcPGPObjectFactory factory = new BcPGPObjectFactory(in);
        Object obj;
        while ((obj = factory.nextObject()) != null)
        {
            if (obj instanceof PGPPublicKeyRing)
            {
                for (Iterator it = ((PGPPublicKeyRing)obj).getPublicKeys(); it.hasNext();)
                {
                    publicKey((PGPPublicKey)it.next());
                }
            }
            else if (obj instanceof PGPSecretKeyRing)
            {
                for (Iterator it = ((PGPSecretKeyRing)obj).getSecretKeys(); it.hasNext();)
                {
                    PGPSecretKey key = (PGPSecretKey)it.next();
                    key.getKeyEncryptionAlgorithm();
                    key.getS2K();
                    publicKey(key.getPublicKey());
                }
            }
            else if (obj instanceof PGPSignatureList)
            {
                PGPSignatureList list = (PGPSignatureList)obj;
                for (int i = 0; i != list.size(); i++)
                {
                    signature(list.get(i));
                }
            }
            else if (obj instanceof PGPOnePassSignatureList)
            {
                PGPOnePassSignatureList list = (PGPOnePassSignatureList)obj;
                for (int i = 0; i != list.size(); i++)
                {
                    list.get(i).getKeyID();
                }
            }
            else if (obj instanceof PGPEncryptedDataList)
            {
                for (Iterator it = ((PGPEncryptedDataList)obj).getEncryptedDataObjects(); it.hasNext();)
                {
                    it.next();
                }
            }
            else if (obj instanceof PGPCompressedData)
            {
                InputStream content = ((PGPCompressedData)obj).getDataStream(READ_LIMIT);
                if (depth < MAX_DEPTH)
                {
                    objects(content, depth + 1);
                }
            }
            else if (obj instanceof PGPLiteralData)
            {
                PGPLiteralData literal = (PGPLiteralData)obj;
                literal.getFileName();
                literal.getModificationTime();
                drain(literal.getDataStream());
            }
        }
    }

    private static void publicKey(PGPPublicKey key)
    {
        key.getKeyID();
        key.getFingerprint();
        key.getAlgorithm();
        key.getBitStrength();
        key.getValidSeconds();
        key.isEncryptionKey();
        for (Iterator it = key.getRawUserIDs(); it.hasNext();)
        {
            it.next();
        }
        for (Iterator it = key.getUserAttributes(); it.hasNext();)
        {
            it.next();
        }
        for (Iterator it = key.getSignatures(); it.hasNext();)
        {
            signature((PGPSignature)it.next());
        }
    }

    private static void signature(PGPSignature sig)
    {
        sig.getSignatureType();
        sig.getKeyID();
        sig.getCreationTime();
        sig.getKeyAlgorithm();
        sig.getHashAlgorithm();
        if (sig.getHashedSubPackets() != null)
        {
            sig.getHashedSubPackets().toArray();
            sig.getHashedSubPackets().getKeyFlags();
            sig.getHashedSubPackets().getKeyExpirationTime();
        }
        if (sig.getUnhashedSubPackets() != null)
        {
            sig.getUnhashedSubPackets().toArray();
        }
    }

    private static void drain(InputStream in)
        throws IOException
    {
        byte[] buf = new byte[4096];
        int total = 0;
        int n;
        while (total < READ_LIMIT && (n = in.read(buf)) >= 0)
        {
            total += n;
        }
    }
}
