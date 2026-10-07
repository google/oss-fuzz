// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in co  mpliance with the License.
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
//////////////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.util.List;

import javax.imageio.IIOException;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.nio.file.Files;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.custom.CustomAnalyzer;
import org.apache.lucene.analysis.synonym.SolrSynonymParser;
import org.apache.lucene.analysis.synonym.WordnetSynonymParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.geo.SimpleWKTShapeParser;
import org.apache.lucene.queryparser.xml.CoreParser;
import org.apache.lucene.queryparser.xml.ParserException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.simple.SimpleQueryParser;
import org.apache.lucene.queryparser.xml.CorePlusQueriesParser;
import org.apache.lucene.queryparser.classic.MultiFieldQueryParser;
import org.apache.lucene.queryparser.flexible.core.QueryNodeException;
import org.apache.lucene.queryparser.flexible.standard.StandardQueryParser;
import org.apache.lucene.queryparser.complexPhrase.ComplexPhraseQueryParser;
import org.apache.lucene.queryparser.flexible.precedence.PrecedenceQueryParser;

public class QueryParserFuzzer {
    static String [] tokenizerArray = {
        "standard",
        "simplePattern",
        "classic",
        "whitespace",
        "uax29UrlEmail",
        "pathHierarchy",
        "wikipedia",
        "nGram",
        "edgeNGram",
        "thai",
        "pattern",
        "simplePatternSplit",
        "letter",
        "keyword"
    };

    static String [] charFilterArray = {
        "htmlStrip",
        "cjkWidth",
        "mapping",
        "patternReplace",
        "persian"
    };

    static String [] tokenFilterArray = {
        "apostrophe",
        "arabicNormalization",
        "arabicStem",
        "asciiFolding",
        "bengaliNormalization",
        "bengaliStem",
        "brazilianStem",
        "bulgarianStem",
        "capitalization",
        "cjkBigram",
        "cjkWidth",
        "classic",
        "codepointCount",
        "commonGrams",
        "commonGramsQuery",
        "concatenateGraph",
        "czechStem",
        "dateRecognizer",
        "decimalDigit",
        "delimitedPayload",
        "delimitedTermFrequency",
        "dictionaryCompoundWord",
        "edgeNGram",
        "elision",
        "englishMinimalStem",
        "englishPossessive",
        "fingerprint",
        "finnishLightStem",
        "fixBrokenOffsets",
        "fixedShingle",
        "flattenGraph", 
        "frenchLightStem", 
        "frenchMinimalStem", 
        "galicianMinimalStem", 
        "galicianStem", 
        "germanLightStem", 
        "germanMinimalStem", 
        "germanNormalization", 
        "germanStem", 
        "greekLowercase", 
        "greekStem", 
        "hindiNormalization", 
        "hindiStem", 
        "hungarianLightStem", 
        "hunspellStem",
        "hyphenatedWords", 
        "hyphenationCompoundWord",
        "indicNormalization", 
        "indonesianStem", 
        "irishLowercase", 
        "italianLightStem", 
        "kStem", 
        "keepWord", 
        "keywordMarker", 
        "keywordRepeat", 
        "latvianStem", 
        "length",
        "limitTokenCount",
        "limitTokenOffset",
        "limitTokenPosition",
        "lowercase", 
        "minHash", 
        "nGram",
        "norwegianLightStem", 
        "norwegianMinimalStem", 
        "numericPayload",
        "patternCaptureGroup",
        "patternReplace",
        "persianNormalization", 
        "porterStem", 
        "portugueseLightStem", 
        "portugueseMinimalStem", 
        "portugueseStem", 
        "protectedTerm",
        "removeDuplicates", 
        "reverseString", 
        "russianLightStem", 
        "scandinavianFolding", 
        "scandinavianNormalization", 
        "serbianNormalization", 
        "shingle", 
        "snowballPorter", 
        "soraniNormalization", 
        "soraniStem", 
        "spanishLightStem", 
        "spanishMinimalStem", 
        "stemmerOverride", 
        "stop", 
        "swedishLightStem", 
        "synonym",
        "synonymGraph",
        "tokenOffsetPayload", 
        "trim", 
        "truncate", 
        "turkishLowercase", 
        "type",
        "typeAsPayload", 
        "typeAsSynonym", 
        "uppercase", 
        "wordDelimiter", 
        "wordDelimiterGraph"
    };

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String field = data.consumeString(500);
        String field2 = data.consumeString(500);
        String field3 = data.consumeString(500);
        String [] fields = {field, field2, field3};
        String query = data.consumeString(500);
        String query2 = data.consumeString(500);
        String query3 = data.consumeString(500);
        String [] queries = {query, query2, query3};
        Boolean dedup = data.consumeBoolean();
        Boolean expand = data.consumeBoolean();
        List<String> selectedTokenizers = data.pickValues(tokenizerArray, data.consumeInt(0, tokenizerArray.length));
        List<String> selectedCharFilters = data.pickValues(charFilterArray, data.consumeInt(0, charFilterArray.length));
        List<String> selectedTokenFilters = data.pickValues(tokenFilterArray, data.consumeInt(0, tokenFilterArray.length));
        CustomAnalyzer.Builder cb = CustomAnalyzer.builder();        

        try {
            cb.withTokenizer(data.pickValue(tokenizerArray));

            for (String cf : selectedCharFilters) {
                cb.addCharFilter(cf);
            }

            for (String tf : selectedTokenFilters) {
                cb.addTokenFilter(tf);
            }

            Analyzer analyzer = cb.build();

            QueryParser queryParser = new QueryParser(field, analyzer);
            queryParser.parse(query);

            StandardQueryParser standardQueryParser = new StandardQueryParser(analyzer);
            standardQueryParser.parse(query, field);

            SimpleQueryParser simpleQueryParser = new SimpleQueryParser(analyzer, field);
            simpleQueryParser.parse(query);
            
            ComplexPhraseQueryParser complexPhraseQueryParser = new ComplexPhraseQueryParser(field, analyzer);
            complexPhraseQueryParser.parse(query); 
            
            MultiFieldQueryParser multiFieldQueryParser = new MultiFieldQueryParser(fields, analyzer);
            multiFieldQueryParser.parse(queries, fields, analyzer); 
            
            PrecedenceQueryParser precedenceQueryParser = new PrecedenceQueryParser(analyzer);
            precedenceQueryParser.parse(query, field);
            
            CoreParser coreParser = new CoreParser(field, analyzer);
            coreParser.parse(new ByteArrayInputStream(query.getBytes()));
            
            CorePlusQueriesParser corePlusQueriesParser = new CorePlusQueriesParser(field, analyzer);
            corePlusQueriesParser.parse(new ByteArrayInputStream(query.getBytes()));
            
            SolrSynonymParser solrqSynonymParser = new SolrSynonymParser(dedup, expand, analyzer);
            solrqSynonymParser.parse(new InputStreamReader(new ByteArrayInputStream(query.getBytes())));
            
            WordnetSynonymParser wordnetSynonymParser = new WordnetSynonymParser(dedup, expand, analyzer);
            wordnetSynonymParser.parse(new InputStreamReader(new ByteArrayInputStream(query.getBytes())));
            
            SimpleWKTShapeParser.parse(query);
        } catch (IOException | QueryNodeException | ParseException | ParserException | java.text.ParseException e) {
            // IOException must be caught or declared to be thrown according to docs.
            // QueryNodeException must be caught or declared to be thrown according to docs.
            // ParseException must be caught or declared to be thrown according to docs.
            // ParserException must be caught or declared to be thrown according to docs.
            // java.text.ParseException must be caught or declared to be thrown according to docs.
        } catch (RuntimeException e) {
            // Undocumented RuntimeException is thrown at https://github.com/apache/lucene/blob/main/lucene/queryparser/src/java/org/apache/lucene/queryparser/complexPhrase/ComplexPhraseQueryParser.java#L147
        } 

    }
}
