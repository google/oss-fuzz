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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * This fuzzer targets the static methods in the DigestUtils class for calculating the hex value of
 * using different hashing methods.
 */
public class DigestUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 12);
      ByteArrayInputStream bais = new ByteArrayInputStream(data.consumeRemainingAsBytes());

      switch (choice) {
        case 1:
          DigestUtils.md2Hex(bais);
          break;
        case 2:
          DigestUtils.md5Hex(bais);
          break;
        case 3:
          DigestUtils.sha1Hex(bais);
          break;
        case 4:
          DigestUtils.sha256Hex(bais);
          break;
        case 5:
          DigestUtils.sha3_224Hex(bais);
          break;
        case 6:
          DigestUtils.sha3_256Hex(bais);
          break;
        case 7:
          DigestUtils.sha384Hex(bais);
          break;
        case 8:
          DigestUtils.sha512Hex(bais);
          break;
        case 9:
          DigestUtils.sha512_224Hex(bais);
          break;
        case 10:
          DigestUtils.sha512_256Hex(bais);
          break;
        case 11:
          DigestUtils.sha512Hex(bais);
          break;
        case 12:
          DigestUtils.shaHex(bais);
          break;
      }
    } catch (IOException e) {
      // Known exception
    }
  }
}
