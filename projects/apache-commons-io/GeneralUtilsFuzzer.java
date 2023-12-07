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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.time.Duration;
import org.apache.commons.io.ByteOrderParser;
import org.apache.commons.io.CopyUtils;
import org.apache.commons.io.EndianUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.ThreadUtils;

/** This fuzzer targets the static methods of the Utils classes in the base package. */
public class GeneralUtilsFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      byte[] outArray = new byte[data.remainingBytes()];
      ByteArrayOutputStream baos = new ByteArrayOutputStream(data.remainingBytes());
      switch (data.consumeInt(1, 15)) {
        case 1:
          ByteOrderParser.parseByteOrder(data.consumeRemainingAsString());
          break;
        case 2:
          CopyUtils.copy(data.consumeRemainingAsString(), baos, Charset.defaultCharset().displayName());
          break;
        case 3:
          EndianUtils.readSwappedDouble(data.consumeRemainingAsBytes(), 0);
          break;
        case 4:
          EndianUtils.readSwappedFloat(data.consumeRemainingAsBytes(), 0);
          break;
        case 5:
          EndianUtils.readSwappedShort(data.consumeRemainingAsBytes(), 0);
          break;
        case 6:
          IOUtils.consume(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
          break;
        case 7:
          byte[] equals = data.consumeRemainingAsBytes();
          IOUtils.contentEquals(new ByteArrayInputStream(equals), new ByteArrayInputStream(equals));
          break;
        case 8:
          IOUtils.copy(new ByteArrayInputStream(data.consumeRemainingAsBytes()), baos);
          break;
        case 9:
          IOUtils.read(new ByteArrayInputStream(data.consumeRemainingAsBytes()), outArray, 0, outArray.length);
          break;
        case 10:
          IOUtils.readFully(new ByteArrayInputStream(data.consumeRemainingAsBytes()), outArray);
          break;
        case 11:
          IOUtils.resourceToByteArray(data.consumeRemainingAsString());
          break;
        case 12:
          IOUtils.resourceToString(data.consumeRemainingAsString(), Charset.defaultCharset());
          break;
        case 13:
          Long skip = data.consumeLong();
          IOUtils.skip(new ByteArrayInputStream(data.consumeRemainingAsBytes()), skip);
          break;
        case 14:
          IOUtils.toByteArray(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
          break;
        case 15:
          ThreadUtils.sleep(Duration.ofSeconds(data.consumeInt(-5, 5)));
          break;
      }
    } catch (IOException | IllegalArgumentException | InterruptedException e) {
      // Known exception
    }
  }
}
