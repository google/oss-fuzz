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

import java.io.IOException;
import java.io.ByteArrayInputStream;
import com.rometools.rome.io.XmlReader;
import com.rometools.rome.io.FeedException;
import com.rometools.rome.io.SyndFeedInput;
import com.rometools.rome.feed.synd.SyndFeed;
import java.lang.IllegalArgumentException;

public class XmlReaderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    ByteArrayInputStream bais = new ByteArrayInputStream(data.consumeRemainingAsBytes());
    try{
      SyndFeed feed = new SyndFeedInput().build(new XmlReader(bais));
    }
    catch( IOException | FeedException | IllegalArgumentException e){
      return;
    }
  
  }
}
