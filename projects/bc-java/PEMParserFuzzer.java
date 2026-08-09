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

import java.io.Reader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ByteArrayInputStream;
import org.bouncycastle.openssl.PEMParser;
import java.io.IOException;
import org.bouncycastle.util.encoders.DecoderException;

public class PEMParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    ByteArrayInputStream bais = new ByteArrayInputStream(data.consumeRemainingAsBytes());
    Reader reader = new BufferedReader(new InputStreamReader(bais));
    PEMParser pemparser = new PEMParser(reader);

    try{
      while (pemparser.readObject() != null){
        //empty body
      }
    }
    catch(IOException | DecoderException e){
      return;
    }

  }
}
