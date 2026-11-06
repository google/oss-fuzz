// Copyright 2026 Google LLC
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

package fuzz.axis2.services;

import java.util.Calendar;

/** Nested POJO bean exercised by BeanUtil (SOAP/RPC) and Gson/Moshi (JSON). */
public class Bean {
    private String name;
    private int id;
    private double value;
    private boolean flag;
    private String[] tags;
    private Bean child;
    private Calendar when;
    private byte[] data;

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public double getValue() { return value; }
    public void setValue(double value) { this.value = value; }
    public boolean isFlag() { return flag; }
    public void setFlag(boolean flag) { this.flag = flag; }
    public String[] getTags() { return tags; }
    public void setTags(String[] tags) { this.tags = tags; }
    public Bean getChild() { return child; }
    public void setChild(Bean child) { this.child = child; }
    public Calendar getWhen() { return when; }
    public void setWhen(Calendar when) { this.when = when; }
    public byte[] getData() { return data; }
    public void setData(byte[] data) { this.data = data; }
}
