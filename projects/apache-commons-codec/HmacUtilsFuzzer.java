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
import java.nio.ByteBuffer;
import java.util.EnumSet;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;

/** This fuzzer targets the hmacHex methods in the HmacUtils class. */
public class HmacUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      Integer choice = data.consumeInt(1, 4);

      // Create HamcUtils object with random algorithm and key bytes
      HmacUtils utils =
          new HmacUtils(
              data.pickValue(EnumSet.allOf(HmacAlgorithms.class)),
              data.consumeBytes(data.remainingBytes()));

      // Fuzz different hmacHex methods in HmacUtils class
      switch (choice) {
        case 1:
          utils.hmacHex(data.consumeRemainingAsBytes());
          break;
        case 2:
          utils.hmacHex(ByteBuffer.wrap(data.consumeRemainingAsBytes()));
          break;
        case 3:
          utils.hmacHex(data.consumeRemainingAsString());
          break;
        case 4:
          utils.hmacHex(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
          break;
      }
    } catch (IOException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
