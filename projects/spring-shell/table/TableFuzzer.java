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
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;

import org.springframework.shell.table.Table;
import org.springframework.shell.table.TableModel;
import org.springframework.shell.table.TableBuilder;
import org.springframework.shell.table.ArrayTableModel;
import org.springframework.shell.table.BorderStyle;

public class TableFuzzer {

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        String header = data.consumeString(250);
        String body = data.consumeString(250);

        TableModel model = new ArrayTableModel(new String[][] {{header, body}, {"",""}});
        Table table = new TableBuilder(model).addHeaderAndVerticalsBorders(BorderStyle.fancy_light).build();

        if (model.transpose().getColumnCount() != 2) {
            throw new FuzzerSecurityIssueMedium("There must be two columns!");
        }
        if (model.transpose().getRowCount() != 2 ) {
            throw new FuzzerSecurityIssueMedium("There must be two rows!");
        }
        if (!((String) model.transpose().getValue(0,0)).equals(header)) {
            throw new FuzzerSecurityIssueMedium("Header is not the same!");
        }
        if (!((String) model.transpose().getValue(1,0)).equals(body)) {
            throw new FuzzerSecurityIssueMedium("Body is not the same!");
        }
    }
}
