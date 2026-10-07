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

import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.LexerInterpreter;
import org.antlr.v4.runtime.ParserInterpreter;
import org.antlr.v4.runtime.RecognitionException;
import org.antlr.v4.tool.LexerGrammar;
import org.antlr.v4.tool.Grammar;

public class GrammarFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {

    LexerGrammar lg;
    Grammar g;
    try{   
      lg = new LexerGrammar(data.consumeString(1000));
      g = new Grammar(data.consumeString(1000));
    }
    catch (org.antlr.runtime.RecognitionException | UnsupportedOperationException e){
      return;
    }

    LexerInterpreter lexEngine = lg.createLexerInterpreter(CharStreams.fromString(data.consumeRemainingAsString()));
    CommonTokenStream tokens = new CommonTokenStream(lexEngine);
    ParserInterpreter parser = g.createParserInterpreter(tokens);
  }
}
