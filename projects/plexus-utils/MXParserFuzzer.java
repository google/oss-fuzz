
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

import java.io.IOException;
import java.io.ByteArrayInputStream;
import org.codehaus.plexus.util.xml.pull.MXParser;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;

public class MXParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    MXParser parser = new MXParser();
    try{
      parser.setInput(new ByteArrayInputStream(data.consumeRemainingAsBytes()), null);
      while( parser.nextToken() != MXParser.END_TAG ){
        //empty body
      }
    }
    catch(XmlPullParserException | IOException e){
      return;
    }
  }
}
