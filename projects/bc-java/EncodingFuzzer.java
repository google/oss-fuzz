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

import java.util.Arrays;

import org.bouncycastle.util.encoders.Base32;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.UrlBase64;

/**
 * Base64, URL-safe Base64, Base32 and Hex: every encoding must decode back to the input, and the
 * decoders, given the raw input itself - mostly not valid in any of them - must either decode it or
 * refuse it with a DecoderException, including through the offset and length variants.
 */
public class EncodingFuzzer
{
    public static void fuzzerTestOneInput(byte[] data)
    {
        roundTrip("Base64", data, Base64.decode(Base64.encode(data)));
        roundTrip("UrlBase64", data, UrlBase64.decode(UrlBase64.encode(data)));
        roundTrip("Base32", data, Base32.decode(Base32.encode(data)));
        roundTrip("Hex", data, Hex.decode(Hex.encode(data)));

        try
        {
            Base64.decode(data);
        }
        catch (DecoderException e)
        {
            // not Base64
        }
        try
        {
            UrlBase64.decode(data);
        }
        catch (DecoderException e)
        {
            // not URL-safe Base64
        }
        try
        {
            Base32.decode(data);
        }
        catch (DecoderException e)
        {
            // not Base32
        }
        try
        {
            Hex.decode(data);
        }
        catch (DecoderException e)
        {
            // not Hex
        }

        // the range variants, over the middle of the input
        int off = data.length / 4;
        int len = data.length / 2;
        try
        {
            byte[] range = Base64.decode(data, off, len);
            if (!Arrays.equals(range, decodeOrNull(Arrays.copyOfRange(data, off, off + len))))
            {
                throw new IllegalStateException("Base64 range decode differs from decoding the range");
            }
        }
        catch (DecoderException e)
        {
            // not Base64
        }
        try
        {
            Hex.decode(data, off, len);
        }
        catch (DecoderException e)
        {
            // not Hex
        }
    }

    private static byte[] decodeOrNull(byte[] data)
    {
        try
        {
            return Base64.decode(data);
        }
        catch (DecoderException e)
        {
            return null;
        }
    }

    private static void roundTrip(String name, byte[] original, byte[] decoded)
    {
        if (!Arrays.equals(original, decoded))
        {
            throw new IllegalStateException(name + " encoding does not decode back to the input: "
                + Hex.toHexString(original));
        }
    }
}
