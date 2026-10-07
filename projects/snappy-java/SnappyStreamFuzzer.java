// Copyright 2023 Google LLC
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

import org.xerial.snappy.Snappy;
import org.xerial.snappy.SnappyInputStream;
import org.xerial.snappy.SnappyOutputStream;
import org.xerial.snappy.SnappyCodec;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;
import java.util.Arrays;

public class SnappyStreamFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {    

    byte[] original = data.consumeRemainingAsBytes();
    byte[] uncompressed;
    
    try {
      ByteArrayOutputStream compressedBuf = new ByteArrayOutputStream();
      SnappyOutputStream snappyOut = new SnappyOutputStream(compressedBuf);
      snappyOut.write(original);
      snappyOut.close();
      byte[] compressed = compressedBuf.toByteArray();
      SnappyInputStream snappyIn = new SnappyInputStream(new ByteArrayInputStream(compressed));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buf = new byte[4096];
      for (int readBytes = 0; (readBytes = snappyIn.read(buf)) != -1; ) {
          out.write(buf, 0, readBytes);
      }
      out.flush();
      uncompressed = out.toByteArray();
    }
    catch (IOException e)
    {
      return;
    }
    
    if(Arrays.equals(original,uncompressed) == false)
    {
      throw new IllegalStateException("Original and uncompressed data are different");
    }    
  }
}
