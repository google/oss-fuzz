/*
 * from https://github.com/apache/axis-axis2-java-core/blob/d8237fd1058354874a3e4c2f07da780a27bcf3ff/modules/samples/quickstart/src/samples/quickstart/service/pojo/StockQuoteService.java
 */

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package samples.quickstart.service.pojo;

import java.util.HashMap;

public class StockQuoteService {
    private HashMap map = new HashMap();

    void printMap(HashMap map) {
        for (Object name: map.keySet()) {
            String key = name.toString();
            String value = map.get(name).toString();
            System.out.println(key + "=" + value);
        }
    }

    public double getPrice(String symbol) {
        Double price = (Double) map.get(symbol);
        if(price != null){
            return price.doubleValue();
        }
        return 42.00;
    }

    public void update(String symbol, double price) {
        map.put(symbol, new Double(price));
    }
}
