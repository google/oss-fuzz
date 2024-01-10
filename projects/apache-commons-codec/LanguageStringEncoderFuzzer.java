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
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringEncoder;
import org.apache.commons.codec.language.Caverphone1;
import org.apache.commons.codec.language.Caverphone2;
import org.apache.commons.codec.language.ColognePhonetic;
import org.apache.commons.codec.language.DaitchMokotoffSoundex;
import org.apache.commons.codec.language.DoubleMetaphone;
import org.apache.commons.codec.language.MatchRatingApproachEncoder;
import org.apache.commons.codec.language.Metaphone;
import org.apache.commons.codec.language.Nysiis;
import org.apache.commons.codec.language.RefinedSoundex;
import org.apache.commons.codec.language.Soundex;
import org.apache.commons.codec.language.bm.BeiderMorseEncoder;

/**
 * This fuzzer targets the encode method in different StringEncoder implementation classes in the
 * language or language.bm package.
 */
public class LanguageStringEncoderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      // Create objects of different StringEncoder implementation classes
      StringEncoder strEncoder = null;

      switch (data.consumeInt(1, 11)) {
        case 1:
          strEncoder = new Caverphone1();
          break;
        case 2:
          strEncoder = new Caverphone2();
          break;
        case 3:
          strEncoder = new ColognePhonetic();
          break;
        case 4:
          strEncoder = new DaitchMokotoffSoundex(data.consumeBoolean());
          break;
        case 5:
          strEncoder = new DoubleMetaphone();
          break;
        case 6:
          strEncoder = new MatchRatingApproachEncoder();
          break;
        case 7:
          strEncoder = new Metaphone();
          break;
        case 8:
          strEncoder = new Nysiis(data.consumeBoolean());
          break;
        case 9:
          strEncoder = new RefinedSoundex(data.consumeString(data.remainingBytes()));
          break;
        case 10:
          strEncoder =
              new Soundex(data.consumeString(data.remainingBytes()), data.consumeBoolean());
          break;
        case 11:
          strEncoder = new BeiderMorseEncoder();
          break;
      }

      // Fuzz encode method of the StringEncoder object
      if (strEncoder != null) {
        strEncoder.encode(data.consumeRemainingAsString());
      }
    } catch (EncoderException | IllegalArgumentException e) {
      // Known exception
    }
  }
}
