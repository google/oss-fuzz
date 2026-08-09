// Copyright 2022 Google LLC
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

import org.springframework.ldap.InvalidNameException;

import static org.springframework.ldap.query.LdapQueryBuilder.query;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.SearchScope;


public class LdapQueryBuilderFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            LdapQuery query = query()
				.base(data.consumeString(100))
				.searchScope(SearchScope.ONELEVEL)
				.timeLimit(30)
				.countLimit(60)
				.where(data.consumeString(100))
                .is(data.consumeString(100))
                .and(data.consumeString(100))
                .is(data.consumeRemainingAsString());
        } catch (InvalidNameException e) {

        }
    }
}