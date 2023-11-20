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
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import org.apache.commons.codec.digest.MurmurHash2;
import org.apache.commons.codec.digest.MurmurHash3;

/**
 * This fuzzer argets different hashing methods in the MurmurHash2 and MurmurHash3 classes of the
 * digest package.
 */
public class MurmurHashFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 12);
      Integer seed = data.consumeInt();
      byte[] byteArray = data.consumeRemainingAsBytes();

      switch (choice) {
        case 1:
          MurmurHash2.hash32(byteArray, byteArray.length, seed);
          break;
        case 2:
          MurmurHash2.hash64(byteArray, byteArray.length, seed);
          break;
        case 3:
          MurmurHash3.hash32x86(byteArray, 0, byteArray.length, seed);
          break;
        case 4:
          MurmurHash3.hash32(ByteBuffer.wrap(byteArray).getLong(), seed);
          break;
        case 5:
          MurmurHash3.hash128x64(byteArray, 0, byteArray.length, seed);
          break;
        case 6:
          MurmurHash3.hash128(byteArray);
          break;
      }
    } catch (BufferUnderflowException e) {
      // Known exception
    }
  }
}
