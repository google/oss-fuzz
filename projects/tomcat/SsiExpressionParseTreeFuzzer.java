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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;

import org.apache.catalina.ssi.*;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public class SsiExpressionParseTreeFuzzer {
    static final long LAST_MODIFIED = 60 * 60 * 24 * 1000;

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String str = data.consumeRemainingAsString();

        try {
            SSIMediator mediator = new SSIMediator(new TesterSSIExternalResolver(), LAST_MODIFIED);
            ExpressionParseTree ept = new ExpressionParseTree(str, mediator);
            ExpressionParseTree ept2 = new ExpressionParseTree(Pattern.quote(str), mediator);
            ept.evaluateTree();
            ept2.evaluateTree();
        } catch (Exception e) {
        }
    }

    public static class TesterSSIExternalResolver implements SSIExternalResolver {
        private Map<String,String> variables = new HashMap<>();

        @Override
        public void addVariableNames(Collection<String> variableNames) {
            // NO-OP
        }

        @Override
        public String getVariableValue(String name) {
            return variables.get(name);
        }

        @Override
        public void setVariableValue(String name, String value) {
            variables.put(name, value);
        }

        @Override
        public Date getCurrentDate() {
            return null;
        }

        @Override
        public long getFileSize(String path, boolean virtual) throws IOException {
            return 0;
        }

        @Override
        public long getFileLastModified(String path, boolean virtual) throws IOException {
            return 0;
        }

        @Override
        public String getFileText(String path, boolean virtual) throws IOException {
            return null;
        }

        @Override
        public void log(String message, Throwable throwable) {
            // NO-OP
        }
    }
}