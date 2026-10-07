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

import org.jdom2.input.SAXBuilder;
import org.jdom2.Document;
import java.io.StringReader;
import org.jdom2.JDOMException;
import java.io.IOException;
import org.jdom2.IllegalNameException;
import org.jdom2.IllegalTargetException;

public class SAXBuilderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    
    SAXBuilder sax = new SAXBuilder();
    sax.setValidation(data.consumeBoolean());
    sax.setIgnoringElementContentWhitespace(data.consumeBoolean());
    sax.setIgnoringBoundaryWhitespace(data.consumeBoolean());
    StringReader xml_input = new StringReader(data.consumeRemainingAsString());
    
    try{    
      Document doc = sax.build(xml_input);
    }
    catch (JDOMException | IOException | IllegalNameException | IllegalTargetException e){
      return;
    }
  }
}
