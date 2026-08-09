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
import org.apache.commons.codec.BinaryDecoder;
import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringDecoder;
import org.apache.commons.codec.StringEncoder;
import org.apache.commons.codec.net.BCodec;
import org.apache.commons.codec.net.PercentCodec;
import org.apache.commons.codec.net.QCodec;
import org.apache.commons.codec.net.QuotedPrintableCodec;
import org.apache.commons.codec.net.URLCodec;

/**
 * This fuzzer targets the encode method in different BinaryEncoder and StringEncoder implementation
 * classes and the decode method in different BinaryDecoder and StringDecoder implementation classes
 * of the net package.
 */
public class NetCodecFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Create objects for fuzzing the encode and decode methods
      BinaryEncoder binEncoder = null;
      BinaryDecoder binDecoder = null;
      StringEncoder strEncoder = null;
      StringDecoder strDecoder = null;

      switch (data.consumeInt(1, 5)) {
        case 1:
          BCodec bCodec = new BCodec();
          strEncoder = bCodec;
          strDecoder = bCodec;
          break;
        case 2:
          PercentCodec pCodec =
              new PercentCodec(data.consumeBytes(data.remainingBytes()), data.consumeBoolean());
          binEncoder = pCodec;
          binDecoder = pCodec;
          break;
        case 3:
          QCodec qCodec = new QCodec();
          strEncoder = qCodec;
          strDecoder = qCodec;
          break;
        case 4:
          QuotedPrintableCodec qPCodec = new QuotedPrintableCodec(data.consumeBoolean());
          binEncoder = qPCodec;
          binDecoder = qPCodec;
          strEncoder = qPCodec;
          strDecoder = qPCodec;
          break;
        case 5:
          URLCodec uCodec = new URLCodec();
          binEncoder = uCodec;
          binDecoder = uCodec;
          strEncoder = uCodec;
          strDecoder = uCodec;
          break;
      }

      // Fuzz encode and decode methods
      if (binEncoder != null) {
        binEncoder.encode(data.consumeRemainingAsBytes());
      }
      if (binDecoder != null) {
        binDecoder.decode(data.consumeRemainingAsBytes());
      }
      if (strEncoder != null) {
        strEncoder.encode(data.consumeRemainingAsString());
      }
      if (strDecoder != null) {
        strDecoder.decode(data.consumeRemainingAsString());
      }
    } catch (EncoderException | DecoderException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
