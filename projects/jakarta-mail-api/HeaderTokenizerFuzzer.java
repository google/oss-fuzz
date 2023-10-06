
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

import jakarta.mail.internet.HeaderTokenizer;
import jakarta.mail.internet.ParseException;

public class HeaderTokenizerFuzzer{
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    HeaderTokenizer ht = new HeaderTokenizer(data.consumeRemainingAsString());
    HeaderTokenizer.Token tok;
    try{
  	  while ((tok = ht.next()).getType() != HeaderTokenizer.Token.EOF){}
    }
    catch(ParseException e){
      return;
    }
  }
}
