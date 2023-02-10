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

import java.util.List;
import java.util.Vector;
import java.lang.IllegalArgumentException;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Order;
import org.springframework.data.jpa.repository.query.QueryUtils;


public class QueryUtilsFuzzer {
    public static Sort.Direction da [] = {Sort.Direction.ASC, Sort.Direction.DESC};
    public static Sort.NullHandling na [] = {Sort.NullHandling.NATIVE, Sort.NullHandling.NULLS_FIRST, Sort.NullHandling.NULLS_LAST};

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        int num = data.consumeInt(0, 200);
        String str = null;
        String str1 = null;
        String str2 = null;

        try {
            List<Order> orders = new Vector<Order>();

            for (int i = 0; i < num; ++i) {
                str = data.consumeString(1000);
                Order o = new Order(data.pickValue(da), str, data.pickValue(na));
                orders.add(o);
            }

            Sort sort = Sort.by(orders);
            str1 = data.consumeString(1000);
            str2 = data.consumeRemainingAsString();
            QueryUtils.applySorting(str1, sort, str2);
        } catch (IllegalArgumentException | org.springframework.dao.InvalidDataAccessApiUsageException e) {
        }

    }

}