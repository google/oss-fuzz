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
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
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
      switch (data.consumeInt(1, 24)) {
        case 1:
          ByteOrderParser.parseByteOrder(data.consumeRemainingAsString());
          break;
        case 2:
          CopyUtils.copy(
              data.consumeRemainingAsString(), baos, Charset.defaultCharset().displayName());
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
          IOUtils.read(
              new ByteArrayInputStream(data.consumeRemainingAsBytes()),
              outArray,
              0,
              outArray.length);
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
          byte[] case15 = data.consumeRemainingAsBytes();
          IOUtils.contentEquals(
              new InputStreamReader(new ByteArrayInputStream(case15)),
              new InputStreamReader(new ByteArrayInputStream(case15)));
          break;
        case 16:
          byte[] case16 = data.consumeRemainingAsBytes();
          IOUtils.contentEqualsIgnoreEOL(
              new InputStreamReader(new ByteArrayInputStream(case16)),
              new InputStreamReader(new ByteArrayInputStream(case16)));
          break;
        case 17:
          IOUtils.copy(
              new ByteArrayInputStream(data.consumeRemainingAsBytes()),
              new OutputStreamWriter(baos),
              Charset.defaultCharset().name());
          break;
        case 18:
          IOUtils.copy(
              new InputStreamReader(new ByteArrayInputStream(data.consumeRemainingAsBytes())),
              new OutputStreamWriter(baos));
          break;
        case 19:
          IOUtils.copyLarge(
              new ByteArrayInputStream(data.consumeRemainingAsBytes()), baos, 0, outArray.length);
          break;
        case 20:
          IOUtils.copyLarge(
              new InputStreamReader(new ByteArrayInputStream(data.consumeRemainingAsBytes())),
              new OutputStreamWriter(baos),
              0,
              outArray.length);
          break;
        case 21:
          IOUtils.readFully(
              new ByteArrayInputStream(data.consumeRemainingAsBytes()), outArray.length);
          break;
        case 22:
          IOUtils.readLines(
              new ByteArrayInputStream(data.consumeRemainingAsBytes()), Charset.defaultCharset());
          break;
        case 23:
          Long skip23 = data.consumeLong();
          IOUtils.skip(
              new InputStreamReader(new ByteArrayInputStream(data.consumeRemainingAsBytes())),
              skip23);
          break;
        case 24:
          ThreadUtils.sleep(Duration.ofSeconds(data.consumeInt(-5, 5)));
          break;
      }
    } catch (IOException | IllegalArgumentException | InterruptedException e) {
      // Known exception
    }
  }
}
