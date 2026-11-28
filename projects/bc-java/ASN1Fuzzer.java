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
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.InMemoryRepresentable;

/**
 * The BER/DER decoder, both the in-memory ASN1InputStream and the streaming ASN1StreamParser, on
 * arbitrary bytes. Every object that decodes is re-encoded as DER, and that DER must decode again to
 * the same DER: a value the library accepts and writes must be one it reads back unchanged.
 */
public class ASN1Fuzzer
{
    public static void fuzzerTestOneInput(byte[] data)
    {
        inMemory(data);
        streaming(data);
    }

    private static void inMemory(byte[] data)
    {
        // the length limit stops a declared length beyond the input allocating more than the input
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(data), data.length);
        try
        {
            ASN1Primitive obj;
            while ((obj = in.readObject()) != null)
            {
                try
                {
                    obj.toString();
                }
                catch (IllegalArgumentException e)
                {
                    // a string type whose content is not valid for it, such as malformed UTF-8
                }
                obj.hashCode();
                checkDERStable(obj);
            }
        }
        catch (IOException e)
        {
            // malformed input
        }
    }

    private static void streaming(byte[] data)
    {
        ASN1StreamParser parser = new ASN1StreamParser(data);
        try
        {
            ASN1Encodable obj;
            while ((obj = parser.readObject()) != null)
            {
                // lazily parsed content reports a malformed encoding with ASN1ParsingException
                if (obj instanceof InMemoryRepresentable)
                {
                    ((InMemoryRepresentable)obj).getLoadedObject();
                }
                else
                {
                    obj.toASN1Primitive();
                }
            }
        }
        catch (IOException | IllegalStateException e)
        {
            // malformed input; ASN1ParsingException is an IllegalStateException
        }
    }

    private static void checkDERStable(ASN1Primitive obj)
        throws IOException
    {
        byte[] der;
        try
        {
            der = obj.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            // content read leniently that has no DER form, such as a non-DER time with the
            // org.bouncycastle.asn1.allow_non_der_time property cleared
            return;
        }
        byte[] again = ASN1Primitive.fromByteArray(der).getEncoded(ASN1Encoding.DER);
        if (!Arrays.equals(der, again))
        {
            throw new IllegalStateException("DER re-encoding is not stable");
        }
    }
}
