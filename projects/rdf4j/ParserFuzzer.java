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
import org.eclipse.rdf4j.query.MalformedQueryException;
import org.eclipse.rdf4j.query.parser.ParsedQuery;
import org.eclipse.rdf4j.query.parser.sparql.SPARQLParser;


// Generated with https://github.com/ossf/fuzz-introspector/tree/main/tools/auto-fuzz
// Heuristic name: jvm-autofuzz-heuristics-2
// Target method: [org.eclipse.rdf4j.query.parser.sparql.SPARQLParser] public org.eclipse.rdf4j.query.parser.ParsedQuery parseQuery(java.lang.String,java.lang.String) throws org.eclipse.rdf4j.query.MalformedQueryException
public class ParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    try {
      SPARQLParser obj = new SPARQLParser();
      obj.parseQuery(
          data.consumeString(data.remainingBytes() / 2), data.consumeRemainingAsString());
    } catch (MalformedQueryException | IllegalArgumentException e1) {
    }
  }
}
