
// Copyright 2021 Google LLC
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import java.util.*;
import java.util.regex.*;
import javax.xml.xpath.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import org.w3c.dom.Attr;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import java.util.HashMap;

public class HamcrestFuzzer {

  HashMap<String, String> hashMap = new HashMap<String, String>();
  HashMap<String, String> hashMap2 = new HashMap<String, String>();

  public HamcrestFuzzer(FuzzedDataProvider data) {
  }

  public void runTest(FuzzedDataProvider data) {

    hashMap.put(data.consumeString(10), data.consumeString(10));
    hashMap2.put(data.consumeString(10), data.consumeString(10));

    try {
      assertThat(data.consumeString(10), containsString(data.consumeString(10)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10),allOf(startsWith(data.consumeString(10)), containsString(data.consumeString(10))));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(hashMap, is(hashMap2));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(hashMap2, is(aMapWithSize(2)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(hashMap2, is(anEmptyMap()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(Arrays.asList(data.consumeString(10), data.consumeString(10)), hasSize(equalTo(2)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(new ArrayList<String>() { { add(data.consumeString(10)); add(data.consumeString(10));}}, is(empty()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(new ArrayList<String>() {{ add(data.consumeString(10)); add(data.consumeString(10));}}, is(emptyCollectionOf(String.class)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(new ArrayList<String>() {{add(data.consumeString(10));add(data.consumeString(10));}}, is(emptyIterable()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(new ArrayList<String>() {{add(data.consumeString(10));add(data.consumeString(10));}}, is(emptyIterableOf(String.class)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(Arrays.asList(data.consumeString(10), data.consumeString(10)),contains(equalTo(data.consumeString(10)), equalTo(data.consumeString(10))));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(Arrays.asList(data.consumeString(10), data.consumeString(10)),containsInAnyOrder(Arrays.asList(equalTo(data.consumeString(10)), equalTo(data.consumeString(10)))));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(hashMap, hasEntry(equalTo(data.consumeString(10)), equalTo(data.consumeString(10))));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(hashMap, hasKey(equalTo(data.consumeString(10))));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(hashMap, hasValue(data.consumeString(10)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), is(in(Arrays.asList(data.consumeString(10), data.consumeString(10)))));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), isOneOf(data.consumeString(10), data.consumeString(10)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), is(oneOf(data.consumeString(10), data.consumeString(10))));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeDouble(), is(closeTo(data.consumeDouble(), data.consumeDouble())));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeDouble(), is(notANumber()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeInt(), comparesEqualTo(data.consumeInt()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeInt(), greaterThan(data.consumeInt()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeInt(), greaterThanOrEqualTo(data.consumeInt()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeInt(), lessThan(data.consumeInt()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeInt(), lessThanOrEqualTo(data.consumeInt()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), equalToIgnoringCase(data.consumeString(10)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), is(emptyString()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), is(blankString()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeInt(), lessThanOrEqualTo(data.consumeInt()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), equalToIgnoringCase(data.consumeString(10)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), is(emptyOrNullString()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), is(blankOrNullString()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), matchesPattern(data.consumeString(10)));
    } catch (AssertionError | PatternSyntaxException e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10),stringContainsInOrder(Arrays.asList(data.consumeString(10), data.consumeString(10))));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeString(10), hasLength(data.consumeInt()));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(data.consumeBoolean(), hasToString(data.consumeString(10)));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      assertThat(Integer.class, typeCompatibleWith(Number.class));
    } catch (AssertionError e) {
      // documented ignore
    }

    try {
      DocumentBuilderFactory documentFactory = DocumentBuilderFactory.newInstance();
      DocumentBuilder documentBuilder = documentFactory.newDocumentBuilder();
      Document document = documentBuilder.newDocument();

      Element root = document.createElement(data.consumeString(10));
      document.appendChild(root);

      Element employee = document.createElement(data.consumeString(10));
      root.appendChild(employee);

      assertThat(root, hasXPath(data.consumeString(10), equalTo(data.consumeString(10))));
    } catch (AssertionError | DOMException | IllegalArgumentException | ParserConfigurationException e) {
      // documented ignore
    }

  }

  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    HamcrestFuzzer testClosure = new HamcrestFuzzer(data);
    testClosure.runTest(data);
  }

}
