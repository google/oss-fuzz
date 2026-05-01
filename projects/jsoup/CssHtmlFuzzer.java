// Copyright 2025 Google LLC
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
/// /////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.jsoup.Jsoup;
import org.jsoup.helper.ValidationException;
import org.jsoup.nodes.Document;
import org.jsoup.select.Evaluator;
import org.jsoup.select.Selector;

public class CssHtmlFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String css = data.consumeString(100);
        Evaluator query;
        try {
            query = Selector.evaluatorOf(css);
        } catch (ValidationException | Selector.SelectorParseException ignored) {
            return;
        }

        String html = data.consumeRemainingAsString();
        Document doc = Jsoup.parse(html, "https://example.com");
        doc.select(query);
    }
}
