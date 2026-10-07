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

import java.util.List;
import java.util.Map;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.felix.utils.json.JSONParser;

public class JSONParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    
    boolean switchConstructor = data.consumeBoolean();
    int switchEncoding = data.consumeInt(0,2);
    String string = data.consumeRemainingAsString();

    try {
      JSONParser jSONParser;
      if (switchConstructor){
        CharSequence charSeq = string;
        jSONParser = new JSONParser(charSeq);
      } else {
        String encoding = "UTF_8";
        switch (switchEncoding) {
          case 0:
            break;
          case 1:
          encoding = "UTF_16";
            break;
          case 2:
          encoding = "UTF_32";
            break;
        }
        
        InputStream inputStream = new ByteArrayInputStream(string.getBytes(encoding));
        jSONParser = new JSONParser(inputStream);
      }
      
      List<Object> res = jSONParser.getParsedList();
      Map<String, Object> parsed = jSONParser.getParsed();
    }
    catch(IllegalArgumentException  | IOException e){
        
    }
  }
  
}
