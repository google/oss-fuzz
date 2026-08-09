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

import java.nio.file.Path;
import java.nio.file.Files;
import java.io.IOException;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.StoredFields;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.TextField;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.util.IOUtils;
import org.apache.lucene.util.automaton.TooComplexToDeterminizeException;


public class IndexSearchFuzzer {
    static Analyzer analyzer = null;
    static Path indexPath = null;
    static Directory directory = null;
    static IndexWriterConfig config = null;
    static IndexWriter iwriter = null;
    static Document doc = null;
    static DirectoryReader ireader = null;
    static IndexSearcher isearcher = null;

    public static void fuzzerInitialize() {
        try {
            analyzer = new StandardAnalyzer();
            indexPath = Files.createTempDirectory("tempIndex");
            directory = FSDirectory.open(indexPath);
            config = new IndexWriterConfig(analyzer);
            iwriter = new IndexWriter(directory, config);
            doc = new Document();
            ireader = DirectoryReader.open(directory);
            isearcher = new IndexSearcher(ireader);
        } catch (IOException e) {
            // IOException must be caught or declared to be thrown according to docs.
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        boolean commit = data.consumeBoolean();
        int n = data.consumeInt();
        String text = data.consumeString(500);
        String field = data.consumeString(500); 
        String queryStr = data.consumeRemainingAsString();
        
        try {
            doc.add(new Field(field, text, TextField.TYPE_STORED));
            iwriter.addDocument(doc);
            iwriter.commit();
            
            QueryParser parser = new QueryParser(field, analyzer);
            Query query = parser.parse(queryStr);
            ScoreDoc[] hits = isearcher.search(query, n).scoreDocs;
        } catch (IOException | ParseException e) {
            // IOException must be caught or declared to be thrown according to docs.
            // ParseException must be caught or declared to be thrown for QueryParser.parse
        } catch (NullPointerException | IllegalArgumentException | TooComplexToDeterminizeException e) {
            // These exceptions are not documented but will be thrown with specific crashing input.
        }
    }
}
