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

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.BaseNCodecInputStream;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base32InputStream;
import org.apache.commons.codec.binary.Base16InputStream;
import org.apache.commons.codec.binary.BaseNCodecOutputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.apache.commons.codec.binary.Base32OutputStream;
import org.apache.commons.codec.binary.Base16OutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

public class BinaryEncodingFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    int selection = data.consumeInt(1,3);
    BaseNCodecInputStream bis;
    BaseNCodecOutputStream bos;
    ByteArrayOutputStream baos;
    String encodingType;
    
    byte[] originalInput = data.consumeRemainingAsBytes();
    final int SIZE = originalInput.length * 2;
    byte[] encoded = new byte[SIZE];

    //Base32 encoding requires 5 bytes per unencoded block
    if(originalInput.length < 5){
      return;
    }

    switch(selection){
      case 1: bis = new Base16InputStream(new ByteArrayInputStream(originalInput), true);
              baos = new ByteArrayOutputStream(SIZE);
              bos = new Base16OutputStream(baos, false);
              encodingType = "Base16";
              break;

      case 2: bis = new Base32InputStream(new ByteArrayInputStream(originalInput), true);
              baos = new ByteArrayOutputStream(SIZE);
              bos = new Base32OutputStream(baos, false);
              encodingType = "Base32";
              break;

      case 3: bis = new Base64InputStream(new ByteArrayInputStream(originalInput), true);
              baos = new ByteArrayOutputStream(SIZE);
              bos = new Base64OutputStream(baos, false);
              encodingType = "Base64";
              break;

      default: return;
    }

    try {
      bis.read(encoded);
    }
    catch (IOException e){
      return;
    }
    
    
    try{
      bos.write(encoded, 0, SIZE);
    }
    catch (IOException e){
      return;
    }

    byte[] decoded = baos.toByteArray();
    
    if(!Arrays.equals(originalInput, decoded)){
      throw new IllegalStateException("Failed to decode: " + Hex.encodeHexString(originalInput) + "\n"
                                    + "Encoded using: " + "<type of encoder>" + "\n"
                                    + "Encoded data: " + Hex.encodeHexString(encoded) + "\n"
                                    + "Decoded data: " + Hex.encodeHexString(decoded) + "\n");
    }

  }
}
