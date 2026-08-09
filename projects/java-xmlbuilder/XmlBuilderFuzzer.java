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
import com.jamesmurty.utils.XMLBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import org.w3c.dom.DOMException;

public class XmlBuilderFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      int[] choices = data.consumeInts(data.consumeInt(1, 10));
      XMLBuilder builder = XMLBuilder.create(data.consumeString(data.remainingBytes() / 2));

      for (Integer choice : choices) {
        switch (choice % 13) {
          case 0:
            builder = builder.stripWhitespaceOnlyTextNodes();
            break;
          case 1:
            builder = builder.up(data.consumeInt());
            break;
          case 2:
            builder = builder.elem(data.consumeRemainingAsString());
            break;
          case 3:
            builder = builder.elementBefore(data.consumeRemainingAsString());
            break;
          case 4:
            builder = builder.attr(
                data.consumeString(data.remainingBytes() / 2), data.consumeRemainingAsString());
            break;
          case 5:
            builder = builder.text(data.consumeRemainingAsString());
            break;
          case 6:
            builder = builder.data(data.consumeRemainingAsString());
            break;
          case 7:
            builder = builder.data(data.consumeRemainingAsBytes());
            break;
          case 8:
            builder = builder.cmnt(data.consumeRemainingAsString());
            break;
          case 9:
            builder = builder.inst(
                data.consumeString(data.remainingBytes() / 2), data.consumeRemainingAsString());
            break;
          case 10:
            builder = builder.insertInstruction(
                data.consumeString(data.remainingBytes() / 2), data.consumeRemainingAsString());
            break;
          case 11:
            builder = builder.ref(data.consumeRemainingAsString());
            break;
          case 12:
            builder = builder.ns(data.consumeRemainingAsString());
            break;
        }
      }
    } catch (ParserConfigurationException | XPathExpressionException | DOMException
        | IllegalStateException e) {
      // Known exception
    }
  }
}
