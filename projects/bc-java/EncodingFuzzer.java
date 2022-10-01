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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import java.lang.StringBuffer;

import java.util.Arrays;

public class EncodingFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    byte[] originalInput = data.consumeRemainingAsBytes();

    byte[] encodedB64 = Base64.encode(originalInput);
    byte[] decodedB64 = Base64.decode(encodedB64);
    if(!Arrays.equals(originalInput, decodedB64)){
      throw new IllegalStateException("Base64 encoding / decoding failure\n" 
                                      + "Original input: " + encodeHexString(originalInput) + "\n"
                                      + "Encoded data: " + encodeHexString(encodedB64) + "\n"
                                      + "Decoded data: " + encodeHexString(decodedB64) + "\n");
    }

    byte[] encodedHex = Hex.encode(originalInput);
    byte[] decodedHex = Hex.decode(encodedHex);

    if(!Arrays.equals(originalInput, decodedHex)){
      throw new IllegalStateException("Hex encoding / decoding failure\n" 
                                      + "Original input: " + encodeHexString(originalInput) + "\n"
                                      + "Encoded data: " + encodeHexString(encodedHex) + "\n"
                                      + "Decoded data: " + encodeHexString(decodedHex) + "\n");
    }
  }
  
  // These two methods were taken from: https://www.baeldung.com/java-byte-arrays-hex-strings
  private static String encodeHexString(byte[] byteArray) {
    StringBuffer hexStringBuffer = new StringBuffer();
    for (int i = 0; i < byteArray.length; i++) {
        hexStringBuffer.append(byteToHex(byteArray[i]));
    }
    return hexStringBuffer.toString();
  }

  private static String byteToHex(byte num) {
      char[] hexDigits = new char[2];
      hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
      hexDigits[1] = Character.forDigit((num & 0xF), 16);
      return new String(hexDigits);
  }
  
}
