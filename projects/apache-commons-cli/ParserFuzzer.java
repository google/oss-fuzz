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

import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;


public class ParserFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {

    DefaultParser parser = new DefaultParser();
    parser = DefaultParser.builder().setStripLeadingAndTrailingQuotes(data.consumeBoolean()).setAllowPartialMatching(data.consumeBoolean()).build();

    Options options = new Options();
    options.addOption("a", "aa", true, "");
    options.addOption("b", "bb", false, "");

    try{
      parser.parse(options, new String[]{data.consumeString(100), data.consumeRemainingAsString()});
    }
    catch (ParseException | StringIndexOutOfBoundsException e){
      return;
    } 

  }
}
