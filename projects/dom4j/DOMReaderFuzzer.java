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

import org.dom4j.io.DOMReader;
import java.io.IOException;
import org.xml.sax.SAXException;
import javax.xml.parsers.ParserConfigurationException;
import java.lang.IllegalArgumentException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.util.List;

public class DOMReaderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder;
    org.w3c.dom.Document doc;

    try{
      builder = factory.newDocumentBuilder();
    }
    catch (ParserConfigurationException e){
      return;
    }

    try{
      doc = builder.parse(new ByteArrayInputStream(data.consumeRemainingAsBytes()));
    }
    catch (SAXException | IOException e){
      return;
    }

    DOMReader reader = new DOMReader();

    try{
      reader.read(doc);
    }
    catch (IllegalArgumentException e){
      return;
    }
  }
}
