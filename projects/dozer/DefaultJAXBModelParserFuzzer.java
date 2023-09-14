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
///////////////////////////////////////////////////////////////////////////
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.xml.sax.SAXException;
import com.github.dozermapper.core.builder.xml.DefaultJAXBModelParser;
import com.github.dozermapper.core.config.BeanContainer;
import java.io.IOException;

// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Minor modifications to beautify code and ensure exception is caught.
// jvm-autofuzz-heuristics-2
// Heuristic name: jvm-autofuzz-heuristics-2
// Target method: [com.github.dozermapper.core.builder.xml.DefaultJAXBModelParser] public void validateXML(java.lang.String) throws org.xml.sax.SAXException,java.io.IOException
public class DefaultJAXBModelParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      DefaultJAXBModelParser obj = new DefaultJAXBModelParser(new BeanContainer());
      obj.validateXML(data.consumeRemainingAsString());
    } catch (SAXException e) {
      // Known exception
    } catch (IOException e) {
      // Known exception
    }
  }
}
