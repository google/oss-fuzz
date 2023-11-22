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
import java.util.zip.Checksum;
import org.apache.commons.codec.digest.PureJavaCrc32;
import org.apache.commons.codec.digest.PureJavaCrc32C;
import org.apache.commons.codec.digest.XXHash32;

/**
 * This fuzzer targets the methods in different Checksum implementation classes in the digest
 * package.
 */
public class ChecksumFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    Checksum checksum = null;

    // Create objects for different checksum implementation classes
    switch (data.consumeInt(1, 3)) {
      case 1:
        checksum = new XXHash32(data.consumeInt());
        break;
      case 2:
        checksum = new PureJavaCrc32();
        break;
      case 3:
        checksum = new PureJavaCrc32C();
        break;
    }

    // Fuzz methods of the Checksum implementation classes
    if (checksum != null) {
      byte[] byteArray = data.consumeRemainingAsBytes();
      checksum.reset();
      checksum.update(byteArray, 0, byteArray.length);
      checksum.getValue();
    }
  }
}
